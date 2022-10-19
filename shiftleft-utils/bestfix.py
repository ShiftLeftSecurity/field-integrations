# Usage: python3 bestfix.py -a app name

import argparse
import csv
import json
import os
import re
import linecache

from six import moves

import sys
import time
import urllib.parse

import httpx
from json2xml import json2xml
from rich.console import Console
from rich.markdown import Markdown
from rich.progress import Progress
from rich.table import Table
from rich.syntax import Syntax

import config
from common import extract_org_id, get_all_apps, get_dataflow, get_findings_url, headers

console = Console(color_system="auto")


def _get_code_line(source_dir, app, fname, line, variables=[]):
    """Return the given line from the file. Handles any utf8 error from tokenize

    :param fname: File name
    :param line: Line number
    :return: Exact line as string
    """
    text = ""
    # For monorepos, app could be inside a directory
    app_path = os.path.join(source_dir, app["id"])
    if os.path.exists(app_path):
        source_dir = app_path
    full_path = os.path.join(source_dir, fname)
    if not os.path.exists(full_path):
        java_path = os.path.join(source_dir, "src", "main", "java", fname)
        if os.path.exists(java_path):
            full_path = java_path
        else:
            scala_path = os.path.join(source_dir, fname)
            if os.path.exists(scala_path):
                full_path = scala_path
            else:
                console.print(f"Unable to locate the file {fname} under {source_dir}")
    try:
        text = linecache.getline(full_path, line)
    except UnicodeDecodeError:
        console.print(
            f"Error parsing the file {full_path} in utf-8. Falling to binary mode"
        )
        with io.open(full_path, "rb") as fp:
            all_lines = fp.readlines()
            if line < len(all_lines):
                text = all_lines[line]
    variable_detected = ""
    for var in variables:
        if var in text:
            if (
                "$" not in var
                and "__" not in var
                and var not in ("this", "self", "req", "res", "p1")
            ):
                variable_detected = var
                text = (
                    text.replace(f"({var}", f"( {var} ")
                    .replace(f"{var})", f" {var} )")
                    .replace(f",{var}", f", {var} ")
                    .replace(f"{var},", f" {var} ,")
                )
                break
    return text, variable_detected


def get_code(source_dir, app, fname, lineno, variables, max_lines=3, tabbed=False):
    """Gets lines of code from a file.

    :param max_lines: Max lines of context to return
    :param tabbed: Use tabbing in the output
    :return: strings of code
    """
    if not fname:
        return ""
    lines = []
    max_lines = max(max_lines, 1)
    lmin = max(1, lineno - max_lines // 2)
    lmax = lmin + max_lines - 1
    variable_detected = ""
    tmplt = "%i\t%s" if tabbed else "%i %s"
    for line in moves.xrange(lmin, lmax):
        text, new_variable_detected = _get_code_line(
            source_dir, app, fname, line, variables
        )
        if not variable_detected and new_variable_detected:
            variable_detected = new_variable_detected
        if isinstance(text, bytes):
            text = text.decode("utf-8", "ignore")

        if not len(text):
            break
        lines.append(tmplt % (line, text))
    if lines:
        return "".join(lines), variable_detected
    else:
        return "", variable_detected


def find_best_fix(org_id, app, scan, findings, source_dir):
    annotated_findings = []
    if not findings:
        return annotated_findings
    console.print("\n\n")
    table = Table(title=f"""Best Fix Suggestions for {app["name"]}""", show_lines=True)
    table.add_column("ID", justify="right", style="cyan")
    table.add_column("Category")
    table.add_column("Locations")
    table.add_column("Code Snippet")
    table.add_column("Comment")
    for afinding in findings:
        category = afinding.get("category")
        # Ignore Sensitive Data Leaks, Sensitive Data Usage and Log Forging for now.
        if "Sensitive" in category or "Log" in category:
            continue
        files_loc_list = []
        tracked_list = []
        source_method = ""
        sink_method = ""
        cvss_31_severity_rating = ""
        cvss_score = ""
        reachability = ""
        details = afinding.get("details", {})
        source_method = details.get("source_method", "")
        sink_method = details.get("sink_method", "")
        tags = afinding.get("tags")
        methods_list = []
        check_methods = set()
        if tags:
            for tag in tags:
                if tag.get("key") == "cvss_31_severity_rating":
                    cvss_31_severity_rating = tag.get("value")
                elif tag.get("key") == "cvss_score":
                    cvss_score = tag.get("value")
                elif tag.get("key") == "reachability":
                    reachability = tag.get("value")
        # For old scans, details block might be empty.
        # We go old school and iterate all dataflows
        dfobj = {}
        if details.get("dataflow"):
            dfobj = details.get("dataflow")
        dataflows = dfobj.get("list", [])
        for df in dataflows:
            variableInfo = df.get("variable_info", {})
            if variableInfo.get("variable"):
                variableInfo = variableInfo.get("variable")
            if variableInfo.get("Variable"):
                variableInfo = variableInfo.get("Variable")
            if variableInfo:
                parameter = variableInfo.get("Parameter")
                if not parameter:
                    parameter = variableInfo.get("parameter")
                local = variableInfo.get("Local")
                member = variableInfo.get("Member")
                if not member:
                    member = variableInfo.get("member")
                if not local:
                    local = variableInfo.get("local")
                if parameter and parameter.get("symbol"):
                    symbol = parameter.get("symbol")
                    if symbol not in tracked_list and symbol not in (
                        "this",
                        "req",
                        "res",
                        "p1",
                    ):
                        tracked_list.append(symbol)
                if member and member.get("symbol"):
                    symbol = member.get("symbol").split(".")[-1]
                    if symbol not in tracked_list and symbol not in (
                        "this",
                        "req",
                        "res",
                        "p1",
                    ):
                        tracked_list.append(symbol)
                if local and local.get("symbol"):
                    symbol = local.get("symbol")
                    if symbol not in tracked_list and symbol not in (
                        "this",
                        "req",
                        "res",
                        "p1",
                    ):
                        tracked_list.append(symbol)
            location = df.get("location", {})
            if location.get("file_name") == "N/A" or not location.get("line_number"):
                continue
            method_name = location.get("method_name")
            short_method_name = location.get("short_method_name")
            if short_method_name and not "empty" in short_method_name:
                # For JavaScript/TypeScript short method name is mostly anonymous
                if "anonymous" in short_method_name:
                    short_method_name = (
                        method_name.split(":anonymous")[0]
                        .split("::")[-1]
                        .split(":")[-1]
                    )
                if short_method_name not in methods_list:
                    methods_list.append(short_method_name)
                for check_labels in ("check", "valid", "sanit"):
                    if check_labels in short_method_name.lower():
                        check_methods.add(method_name)
            if not source_method:
                source_method = (
                    f'{location.get("file_name")}:{location.get("line_number")}'
                )
            loc_line = f'{location.get("file_name")}:{location.get("line_number")}'
            if loc_line not in files_loc_list:
                files_loc_list.append(loc_line)
        if dataflows and dataflows[-1]:
            sink = dataflows[-1].get("location", {})
            if sink and not sink_method:
                sink_method = f'{sink.get("file_name")}:{sink.get("line_number")}'

        if afinding.get("type") in ("vuln"):
            methods_list = methods_list
            check_methods = list(check_methods)
            last_location = files_loc_list[-1]
            # Ignore html files
            if "html" in last_location and len(files_loc_list) > 2:
                last_location = files_loc_list[-2]
            first_location = files_loc_list[0]
            tmpA = last_location.split(":")
            tmpB = first_location.split(":")
            last_location_fname = tmpA[0]
            last_location_lineno = int(tmpA[-1])
            first_location_fname = tmpB[0]
            first_location_lineno = int(tmpB[-1])
            code_snippet, variable_detected = get_code(
                source_dir, app, last_location_fname, last_location_lineno, tracked_list
            )
            # Arrive at a best fix
            best_fix = ""
            location_suggestion = (
                f"- Before or at line {last_location_lineno} in {last_location_fname}"
            )
            if (
                first_location_fname != last_location_fname
                or last_location_lineno - first_location_lineno > 3
            ):
                location_suggestion = (
                    location_suggestion
                    + f"\n- After line {first_location_lineno} in {first_location_fname}"
                )
            if source_method == sink_method:
                best_fix = f"""This is likely a best practice finding or a false positive.

**Fix locations:**\n
{location_suggestion}

**Remediation suggestions:**\n
Specify the sink method in your remediation config to suppress this finding.\n
- {sink_method}

"""
            elif variable_detected:
                best_fix = f"""**Taint:** Parameter `{variable_detected}` in the method `{methods_list[-1]}`\n
Validate or Sanitize the parameter `{variable_detected}` before invoking the sink `{sink_method}`

**Fix locations:**\n
{location_suggestion}
"""
            elif tracked_list:
                variable_detected = tracked_list[0]
                # No variable detected but taint list available
                best_fix = f"""**Taint:** Parameter `{variable_detected}` in the method `{methods_list[-1]}`\n
Validate or Sanitize the parameter `{variable_detected}` before invoking the sink `{sink_method}`

**Fix locations:**\n
{location_suggestion}
"""
            if check_methods:
                best_fix = (
                    best_fix
                    + f"""
**Remediation suggestions:**\n
Include these detected CHECK methods in your remediation config to suppress this finding.\n
- {"- ".join(check_methods)}
"""
                )
            deep_link = f"""https://app.shiftleft.io/apps/{app["id"]}/vulnerabilities?scan={scan.get("id")}&findingId={afinding.get("id")}"""
            app_language = scan.get("language", "java")
            comment_str = "//"
            if app_language == "python":
                comment_str = "#"
            table.add_row(
                f"""[link={deep_link}]{afinding.get("id")}[/link]""",
                afinding.get("category"),
                "\n".join(files_loc_list),
                Syntax(
                    f"{comment_str} {last_location_fname}\n\n" + code_snippet,
                    app_language,
                ),
                Markdown(best_fix),
            )
            annotated_finding = {
                "id": afinding.get("id"),
                "category": afinding.get("category"),
                "title": afinding.get("title"),
                "version_first_seen": afinding.get("version_first_seen"),
                "scan_first_seen": afinding.get("scan_first_seen"),
                "internal_id": afinding.get("internal_id"),
                "cvss_31_severity_rating": cvss_31_severity_rating,
                "cvss_score": cvss_score,
                "reachability": reachability,
                "source_method": source_method,
                "sink_method": sink_method,
                "last_location": last_location,
                "variable_detected": variable_detected,
                "tracked_list": "\n".join(tracked_list),
                "check_methods": "\n".join(check_methods),
                "code_snippet": code_snippet.replace("\n", "\\n"),
                "best_fix": best_fix.replace("\n", "\\n"),
            }
            annotated_findings.append(annotated_finding)
    console.print(table)
    return annotated_findings


def export_csv(app, annotated_findings, report_file):
    if annotated_findings:
        fieldnames = annotated_findings[0].keys()
        if not os.path.exists(report_file):
            with open(report_file, "w", newline="") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
        with open(report_file, "a", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            for finding in annotated_findings:
                writer.writerow(finding)
            console.print(f"CSV exported to {report_file}")


def get_all_findings_with_scan(
    client, org_id, app_name, version, ratings=["critical", "high"]
):
    """Method to retrieve all findings"""
    findings_list = []
    version_suffix = f"&version={version}" if version else ""
    findings_url = f"https://{config.SHIFTLEFT_API_HOST}/api/v4/orgs/{org_id}/apps/{app_name}/findings?per_page=249&type=oss_vuln&type=vuln&include_dataflows=true{version_suffix}"
    for rating in ratings:
        findings_url = f"{findings_url}&finding_tags=cvss_31_severity_rating={rating}"
    page_available = True
    scan = {}
    while page_available:
        try:
            r = client.get(findings_url, headers=headers, timeout=config.timeout)
        except httpx.ReadTimeout as e:
            console.print(
                f"Unable to retrieve findings for {app_name} due to timeout after {config.timeout} seconds"
            )
            continue
        if r.status_code == 200:
            raw_response = r.json()
            if raw_response and raw_response.get("response"):
                response = raw_response.get("response")
                total_count = response.get("total_count")
                scan = response.get("scan")
                if not scan:
                    page_available = False
                    continue
                scan_id = scan.get("id")
                spid = scan.get("internal_id")
                projectSpId = f'sl/{org_id}/{scan.get("app")}'
                findings = response.get("findings")
                if not findings:
                    page_available = False
                    continue
                counts = response.get("counts")
                findings_list += findings
                if raw_response.get("next_page"):
                    parsed = urllib.parse.urlparse(raw_response.get("next_page"))
                    findings_url = parsed._replace(
                        netloc=config.SHIFTLEFT_API_HOST
                    ).geturl()
                else:
                    page_available = False
        else:
            page_available = False
            console.print(
                f"Unable to retrieve findings for {app_name} due to http error {r.status_code}"
            )
    return scan, findings_list


def export_report(org_id, app_list, report_file, rformat, source_dir):
    if not app_list:
        app_list = get_all_apps(org_id)
    work_dir = os.getcwd()
    for e in ["GITHUB_WORKSPACE", "WORKSPACE"]:
        if os.getenv(e):
            work_dir = os.getenv(e)
            break
    with Progress(
        transient=True,
        redirect_stderr=False,
        redirect_stdout=False,
        refresh_per_second=1,
    ) as progress:
        task = progress.add_task(
            f"[green] Identifying best fixes for {len(app_list)} apps",
            total=len(app_list),
            start=True,
        )
        limits = httpx.Limits(
            max_keepalive_connections=20, max_connections=100, keepalive_expiry=120
        )
        with httpx.Client(http2="win" not in sys.platform, limits=limits) as client:
            for app in app_list:
                app_id = app.get("id")
                app_name = app.get("name")
                progress.update(task, description=f"Processing [bold]{app_name}[/bold]")
                scan, findings = get_all_findings_with_scan(
                    client, org_id, app_id, None
                )
                annotated_findings = find_best_fix(
                    org_id, app, scan, findings, source_dir
                )
                if rformat == "csv":
                    export_csv([app], annotated_findings, report_file)
                progress.advance(task)


def build_args():
    """
    Constructs command line arguments for the export script
    """
    parser = argparse.ArgumentParser(description="ShiftLeft NG SAST export script")
    parser.add_argument(
        "-a",
        "--app",
        dest="app_name",
        help="App name",
        default=config.SHIFTLEFT_APP,
    )
    parser.add_argument(
        "-s", "--source_dir", dest="source_dir", help="Source directory"
    )
    parser.add_argument(
        "-o",
        "--report_file",
        dest="report_file",
        help="Report filename",
        default="ngsast-bestfix-report.csv",
    )
    parser.add_argument(
        "-f",
        "--format",
        dest="rformat",
        help="Report format",
        default="csv",
        choices=["csv"],
    )
    return parser.parse_args()


if __name__ == "__main__":
    if not config.SHIFTLEFT_ACCESS_TOKEN:
        console.print(
            "Set the environment variable SHIFTLEFT_ACCESS_TOKEN before running this script"
        )
        sys.exit(1)

    org_id = extract_org_id(config.SHIFTLEFT_ACCESS_TOKEN)
    if not org_id:
        console.print(
            "Ensure the environment varibale SHIFTLEFT_ACCESS_TOKEN is copied exactly as-is from the website"
        )
        sys.exit(1)

    console.print(config.ngsast_logo)
    start_time = time.monotonic_ns()
    args = build_args()
    app_list = []
    if args.app_name:
        app_list.append({"id": args.app_name, "name": args.app_name})
    report_file = args.report_file
    source_dir = args.source_dir
    if not source_dir:
        console.print(
            f"WARN: Source directory not specified with -s argument. Assuming current directory!"
        )
        source_dir = os.getcwd()
        for e in ["GITHUB_WORKSPACE", "WORKSPACE"]:
            if os.getenv(e):
                source_dir = os.getenv(e)
                break
    export_report(org_id, app_list, report_file, args.rformat, source_dir)
    end_time = time.monotonic_ns()
    total_time_sec = round((end_time - start_time) / 1000000000, 2)
