# Usage: python3 export.py -a app name

import argparse
import csv
import json
import os
import sys
import time
import urllib.parse

import httpx
import convert2sarif as convertLib
from json2xml import json2xml
from rich.console import Console
from rich.progress import Progress

import config
from common import extract_org_id, get_all_apps, get_findings_url, headers

console = Console(color_system="auto")


def export_csv(app_list, findings, report_file):
    if not os.path.exists(report_file):
        with open(report_file, "w", newline="") as csvfile:
            reportwriter = csv.writer(
                csvfile,
                dialect="excel",
                delimiter=",",
                quotechar='"',
                quoting=csv.QUOTE_MINIMAL,
            )
            reportwriter.writerow(
                [
                    "App",
                    "App Group",
                    "Finding ID",
                    "Type",
                    "Category",
                    "OWASP Category",
                    "Severity",
                    "Source Method",
                    "Sink Method",
                    "Source File",
                    "Version First Seen",
                    "Scan First Seen",
                    "Internal ID",
                    "CVSS 3.1 Rating",
                    "CVSS Score",
                    "Reachability",
                ]
            )
    with open(report_file, "a", newline="") as csvfile:
        reportwriter = csv.writer(
            csvfile,
            dialect="excel",
            delimiter=",",
            quotechar='"',
            quoting=csv.QUOTE_MINIMAL,
        )
        for app in app_list:
            app_name = app.get("name")
            tags = app.get("tags")
            app_group = ""
            if tags:
                for tag in tags:
                    if tag.get("key") == "group":
                        app_group = tag.get("value")
                        break
            source_method = ""
            sink_method = ""
            cvss_31_severity_rating = ""
            cvss_score = ""
            reachability = ""
            files_loc_list = set()
            # Find the source, sink and other tags
            for afinding in findings:
                details = afinding.get("details", {})
                source_method = details.get("source_method", "")
                sink_method = details.get("sink_method", "")
                tags = afinding.get("tags")
                if tags:
                    for tag in tags:
                        if tag.get("key") == "cvss_31_severity_rating":
                            cvss_31_severity_rating = tag.get("value")
                        elif tag.get("key") == "cvss_score":
                            cvss_score = tag.get("value")
                        elif tag.get("key") == "reachability":
                            reachability = tag.get("value")
                if details.get("file_locations"):
                    files_loc_list.update(details.get("file_locations"))
                # For old scans, details block might be empty.
                # We go old school and iterate all dataflows
                if not source_method or not sink_method or not files_loc_list:
                    dfobj = {}
                    if details.get("dataflow"):
                        dfobj = details.get("dataflow")
                    dataflows = dfobj.get("list", [])
                    files_loc_list = set()
                    for df in dataflows:
                        location = df.get("location", {})
                        if location.get("file_name") == "N/A" or not location.get(
                            "line_number"
                        ):
                            continue
                        if not source_method:
                            source_method = f'{location.get("file_name")}:{location.get("line_number")}'
                        files_loc_list.add(
                            f'{location.get("file_name")}:{location.get("line_number")}'
                        )
                    if dataflows and dataflows[-1]:
                        sink = dataflows[-1].get("location", {})
                        if sink:
                            sink_method = (
                                f'{sink.get("file_name")}:{sink.get("line_number")}'
                            )
                if afinding.get("type") in (
                    "oss_vuln",
                    "container",
                    "extscan",
                    "secret",
                ):
                    reportwriter.writerow(
                        [
                            app_name,
                            app_group,
                            afinding.get("id"),
                            afinding.get("type"),
                            afinding.get("category"),
                            afinding.get("owasp_category"),
                            afinding.get("severity"),
                            "",
                            "",
                            afinding.get("title"),
                            afinding.get("version_first_seen"),
                            afinding.get("scan_first_seen"),
                            afinding.get("internal_id"),
                            cvss_31_severity_rating,
                            cvss_score,
                            reachability,
                        ]
                    )
                elif afinding.get("type") in ("vuln"):
                    for loc in files_loc_list:
                        reportwriter.writerow(
                            [
                                app_name,
                                app_group,
                                afinding.get("id"),
                                afinding.get("type"),
                                afinding.get("category"),
                                afinding.get("owasp_category"),
                                afinding.get("severity"),
                                source_method,
                                sink_method,
                                loc,
                                afinding.get("version_first_seen"),
                                afinding.get("scan_first_seen"),
                                afinding.get("internal_id"),
                                cvss_31_severity_rating,
                                cvss_score,
                                "reachable"
                                if afinding.get("related_findings", [])
                                else "N/A",
                            ]
                        )


def get_all_findings(client, org_id, app_name, version):
    """Method to retrieve all findings"""
    findings_list = []
    findings_url = get_findings_url(org_id, app_name, version, None)
    page_available = True
    scan = None
    counts = None
    while page_available:
        try:
            r = client.get(findings_url, headers=headers, timeout=config.timeout)
        except Exception:
            console.print(
                f"Unable to retrieve findings for {app_name} due to exception after {config.timeout} seconds"
            )
            page_available = False
            continue
        if r.status_code == 200:
            raw_response = r.json()
            if raw_response and raw_response.get("response"):
                response = raw_response.get("response")
                scan = response.get("scan")
                counts = response.get("counts")
                if not scan:
                    page_available = False
                    continue
                findings = response.get("findings")
                if not findings:
                    page_available = False
                    continue
                if os.getenv("TRIM_DESCRIPTION"):
                    for f in findings:
                        f["description"] = ""
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
    return findings_list, scan, counts


def export_report(org_id, app_list, report_file, reports_dir, format):
    if not app_list:
        app_list = get_all_apps(org_id)
    # This might increase memory consumption for large organizations
    findings_dict = {}
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
        if len(app_list) > 50:
            progress.console.print(
                f"Export process would take a while for {len(app_list)} apps.\nUse SARIF or xml format to avoid crashes."
            )
        task = progress.add_task(
            f"[green] Export Findings for {len(app_list)} apps",
            total=len(app_list),
            start=True,
        )
        limits = httpx.Limits(
            max_keepalive_connections=20, max_connections=100, keepalive_expiry=120
        )
        with httpx.Client(http2="win32" not in sys.platform, limits=limits) as client:
            for app in app_list:
                app_id = app.get("id")
                app_name = app.get("name")
                progress.update(task, description=f"Processing [bold]{app_name}[/bold]")
                findings, scan, counts = get_all_findings(client, org_id, app_id, None)
                file_category_set = set()
                if format == "xml" or report_file.endswith(".xml"):
                    app_report_file = report_file.replace(".xml", "-" + app_id + ".xml")
                    with open(app_report_file, mode="w") as rp:
                        xml_data = json2xml.Json2xml(findings).to_xml()
                        if xml_data:
                            rp.write(xml_data)
                            progress.console.print(
                                f"Findings report successfully exported to {app_report_file}"
                            )
                elif format == "raw":
                    app_json_file = report_file.replace(".json", "-" + app_id + ".json")
                    with open(app_json_file, mode="w") as rp:
                        json.dump(
                            {
                                "name": app_name,
                                "scan": scan,
                                "findings": findings,
                                "counts": counts,
                            },
                            rp,
                            ensure_ascii=True,
                            indent=None,
                        )
                        rp.flush()
                        progress.console.print(
                            f"Json file successfully exported to {app_json_file}"
                        )
                elif format == "sarif":
                    app_sarif_file = report_file.replace(
                        ".sarif", "-" + app_id + ".sarif"
                    )
                    app_json_file = app_sarif_file.replace(".sarif", ".json")
                    with open(app_json_file, mode="w") as rp:
                        json.dump(
                            {app_name: findings},
                            rp,
                            ensure_ascii=True,
                            indent=None,
                        )
                        rp.flush()
                    convertLib.convert_file(
                        "ng-sast",
                        os.getenv("TOOL_ARGS", ""),
                        work_dir,
                        app_json_file,
                        app_sarif_file,
                        None,
                    )
                    progress.console.print(
                        f"SARIF file successfully exported to {app_sarif_file}"
                    )
                    os.remove(app_json_file)
                elif format == "sl":
                    with open(report_file, mode="w") as rp:
                        for af in findings:
                            details = af.get("details")
                            title = af.get("title")
                            # filename could be found either in file_locations or fileName
                            filename = ""
                            if details and details.get("file_locations"):
                                file_locations = details.get("file_locations")
                                if len(file_locations):
                                    filename = (
                                        file_locations[0].split(":")[0].split("/")[-1]
                                    )
                                    filename = filename.replace(".java", "")
                            # If there is no file_locations try to extract the name from the title
                            if not filename and "BenchmarkTest" in title:
                                filename = (
                                    title.split(" in ")[-1]
                                    .replace("`", "")
                                    .split(".")[0]
                                )
                            if filename.startswith("BenchmarkTest"):
                                filename = filename.replace("BenchmarkTest", "")
                            else:
                                # Try to get the filename from source_method in details
                                source_method = details.get("source_method")
                                if source_method and "BenchmarkTest" in source_method:
                                    filename = source_method.split(":")[0].split(".")[4]
                                    filename = filename.replace("BenchmarkTest", "")
                                else:
                                    progress.console.print(
                                        f'Get dataflow for {af.get("id")}'
                                    )
                                    dataflows = details.get("dataflow", {}).get("list")
                                    if dataflows:
                                        for df in dataflows:
                                            location = df.get("location")
                                            if location.get(
                                                "class_name"
                                            ) and "BenchmarkTest" in location.get(
                                                "class_name"
                                            ):
                                                filename = location.get(
                                                    "class_name"
                                                ).split(".")[-1]
                                                filename = filename.replace(
                                                    "BenchmarkTest", ""
                                                )
                                                break
                            if not filename.isnumeric():
                                progress.console.print(f"finding ID {af.get('id')} is in the benchmark harness")
                                continue
                            if not filename:
                                progress.console.print(
                                    f"Unable to extract filename from file_locations or title {title}. Skipping ..."
                                )
                                continue
                            cwes = (
                                int(pair["value"])
                                for pair in af["tags"]
                                if pair["key"] == "cwe_category"
                            )
                            categories = (
                                config.sl_owasp_category[cwe]
                                for cwe in cwes
                                if cwe in config.sl_owasp_category
                            )
                            try:
                                category = next(categories)
                                file_category = f"{filename},{category}"
                                if file_category not in file_category_set:
                                    rp.write(file_category + "\n")
                                    file_category_set.add(file_category)
                            except StopIteration:
                                pass
                        progress.console.print(
                            f"Findings report successfully exported to {report_file}"
                        )
                elif format == "csv":
                    export_csv([app], findings, report_file)
                else:
                    findings_dict[app_name] = findings
                progress.advance(task)
    if format == "json":
        with open(report_file, mode="w") as rp:
            json.dump(findings_dict, rp, ensure_ascii=True, indent=config.json_indent)
            console.print(f"JSON report successfully exported to {report_file}")


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
        action='append', 
        nargs='+',
    )
    parser.add_argument(
        "-o",
        "--report_file",
        dest="report_file",
        help="Report filename",
        default="ngsast-report.csv",
    )
    parser.add_argument("--reports_dir", dest="reports_dir", help="Reports directory")
    parser.add_argument(
        "-f",
        "--format",
        dest="format",
        help="Report format",
        default="csv",
        choices=["json", "xml", "csv", "sl", "sarif", "raw"],
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
        for eachApp in args.app_name:
            app_list.append({"id": eachApp[0], "name": eachApp[0]})
    report_file = args.report_file
    reports_dir = args.reports_dir
    format = args.format
    # Fix file extensions for xml format
    if format == "xml":
        report_file = report_file.replace(".csv", ".xml")
    if format == "sarif":
        report_file = report_file.replace(".csv", ".sarif")
    if format == "raw":
        report_file = report_file.replace(".csv", ".json")
    elif format == "sl":
        if not args.app_name:
            console.print(
                "This format is only suitable for OWASP Benchmark purposes. Use json or csv for all other apps"
            )
            sys.exit(1)
        if not report_file:
            report_file = "Benchmark_1.2-ShiftLeft.sl"
    if reports_dir:
        os.makedirs(reports_dir, exist_ok=True)
        report_file = os.path.join(reports_dir, report_file)
    export_report(org_id, app_list, report_file, reports_dir, format)
    end_time = time.monotonic_ns()
    total_time_sec = round((end_time - start_time) / 1000000000, 2)
