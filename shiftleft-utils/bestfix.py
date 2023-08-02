# Usage: python3 bestfix.py -a app name

import argparse
import csv
import io
import logging
import linecache
import math
import os
import re
import sys
import time
import urllib.parse
from collections import defaultdict
from urllib.parse import unquote

import httpx
from packaging.version import parse
from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress
from rich.syntax import Syntax
from rich.table import Table
from rich.terminal_theme import DEFAULT_TERMINAL_THEME, MONOKAI
from rich.theme import Theme
from rich.tree import Tree
from six import moves

import config
import gh as GitHubLib
from common import extract_org_id, get_all_apps, get_scan_run, headers

LOG = logging.getLogger(__name__)
for _ in ("httpx",):
    logging.getLogger(_).disabled = True

CI_MODE = os.getenv("CI") in ("true", "1") or os.getenv("AGENT_OS") is not None

custom_theme = Theme({"info": "cyan", "warning": "purple4", "danger": "bold red"})
console = None
if CI_MODE:
    console = Console(
        log_time=False,
        log_path=False,
        color_system="256",
        force_terminal=True,
        width=int(os.getenv("COLUMNS", 250)),
        record=True,
    )
else:
    console = Console(
        log_time=False,
        log_path=False,
        theme=custom_theme,
        color_system="auto",
        force_terminal=True,
        record=True,
    )

MD_LIST_MARKER = "\n- "

pdf_options = {
    "page-size": "A2",
    "margin-top": "0.5in",
    "margin-right": "0.25in",
    "margin-bottom": "0.5in",
    "margin-left": "0.25in",
    "encoding": "UTF-8",
    "no-outline": None,
}


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
                # console.print(f"Unable to locate the file {fname} under {source_dir}")
                return "", "", ""
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
    for var in variables[::-1]:
        if var in text:
            if "$" not in var and var not in ("this", "self", "req", "res", "p1"):
                variable_detected = var
                text = (
                    text.replace(f"({var}", f"( {var} ")
                    .replace(f"{var})", f" {var} )")
                    .replace(f",{var}", f", {var} ")
                    .replace(f"{var},", f" {var} ,")
                    .replace(f"+{var}", f"+ {var} ")
                )
                break
    return text, variable_detected, full_path


def get_code(source_dir, app, fname, lineno, variables, max_lines=3, tabbed=False):
    """Gets lines of code from a file.

    :param max_lines: Max lines of context to return
    :param tabbed: Use tabbing in the output
    :return: strings of code
    """
    if not fname:
        return "", "", ""
    lines = []
    max_lines = max(max_lines, 1)
    lmin = max(1, lineno - max_lines // 2)
    lmax = lmin + max_lines
    variable_detected = ""
    tmplt = "%i\t%s" if tabbed else "%i %s"
    full_path = ""
    for line in moves.xrange(lmin, lmax):
        text, new_variable_detected, full_path = _get_code_line(
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
        return "".join(lines), variable_detected, full_path
    else:
        return "", variable_detected, full_path


def to_local_path(full_path_prefix, fl):
    full_file_path = f"{full_path_prefix}{fl}"
    if "win32" in sys.platform:
        full_file_path = "/" + full_file_path.replace("\\", "/")
    return f"file://{full_file_path}"


def find_ignorables(app_language, last_location_fname, files_loc_list):
    ignorables_list = set()
    for fl in files_loc_list:
        for igpattern in config.ignorable_paths:
            if igpattern in fl.lower():
                ignorables_list.add(fl)
                break
    return list(ignorables_list)


def get_category_suggestion(
    category, variable_detected, source_method, sink_method, ptags_set, mtags_set
):
    suppressable_finding = False
    category_suggestion = ""
    if category in ("Remote Code Execution", "Potential Remote Code Execution"):
        if variable_detected:
            category_suggestion = f"""Use an allowlist for approved commands and compare the variables `{variable_detected}` against this list in a new validation method. Then, specify this validation method name in the remediation config file."""
        else:
            category_suggestion = "This is an informational finding."
            suppressable_finding = True
    elif category == "SQL Injection":
        if "stringManipulation" in ptags_set:
            category_suggestion = f"""Use any alternative SQL method with builtin parameterization capability instead of string manipulation methods. Parameterize and validate the variables `{variable_detected}` before invoking the SQL method `{sink_method}`."""
        else:
            category_suggestion = f"""Use any alternative SQL method with builtin parameterization capability. Parameterize and validate the variables `{variable_detected}` before invoking the SQL method `{sink_method}`."""
    elif category == "NoSQL Injection":
        category_suggestion = f"""Use any alternative SDK method with builtin parameterization capability. Parameterize and validate the variables `{variable_detected}` before invoking the NoSQL method `{sink_method}`."""
    elif category == "Directory Traversal":
        category_suggestion = f"""Use an allowlist of safe file or URL locations and compare `{variable_detected}` against this list before invoking the method `{sink_method}`."""
    elif category in ("Deserialization", "Deserialization of HTTP data"):
        if sink_method in ("json.loads"):
            category_suggestion = f"""This is an informational finding since the sink method `{sink_method}` is safe by default."""
            suppressable_finding = True
        else:
            category_suggestion = """Follow security best practices to configure and use the deserialization library in a safe manner. Depending on the version of the library used, this vulnerability could be difficult to exploit."""
    elif category in (
        "SSRF",
        "Server-Side Request Forgery",
        "Potential Server-Side Request Forgery",
    ):
        if not variable_detected:
            category_suggestion = ""
            suppressable_finding = True
        elif variable_detected == variable_detected.upper():
            category_suggestion = f"""This is an informational finding since the variable `{variable_detected}` could either be a constant or belong to a trusted endpoint."""
            suppressable_finding = True
        elif "httpClient" in ptags_set:
            category_suggestion = """This finding is not attacker reachable since the source parameter is an http client."""
            suppressable_finding = True
        elif "__POLYMORPHIC__" in sink_method:
            category_suggestion = f"""This is an informational finding since the code could be performing an internal redirection or an API call. Specify `{sink_method}` in your remediation config to suppress this finding."""
            suppressable_finding = True
        else:
            category_suggestion = f"""Validate and ensure `{variable_detected}` does not contain URLs and other malicious input. For externally injected values, compare `{variable_detected}` against an allowlist of approved URL domains or service IP addresses. Then, specify this validation method name or the source method `{source_method}` in the remediation config file to suppress this finding."""
    elif category == "XML External Entities":
        category_suggestion = """Follow security best practices to configure and use the XML library in a safe manner."""
    elif category in ("Cross-Site Scripting", "XSS"):
        if source_method == "^__node^.process.%env":
            category_suggestion = """This is an informational finding since reading an environment variable using `process.env` is safe by default."""
            suppressable_finding = True
        elif variable_detected:
            category_suggestion = f"""Ensure the variable `{variable_detected}` are encoded or sanitized before returning via HTML or API response."""
        else:
            category_suggestion = """Ensure all user input variables are encoded or sanitized before returning via HTML or API response."""
    elif category == "LDAP Injection":
        category_suggestion = f"""Ensure the variable `{variable_detected}` are encoded or sanitized before invoking the LDAP method `{sink_method}`."""
    elif category in ("Hardcoded Credentials", "Weak Hash"):
        if '"' in variable_detected:
            category_suggestion = f"""Ensure `{variable_detected}` is the correct value in this context before invoking the sink method `{sink_method}`."""
        elif variable_detected:
            category_suggestion = f"""Ensure `{variable_detected}` has the required value for this application or context before invoking the sink method `{sink_method}`."""
        else:
            category_suggestion = (
                f"""Ensure the inputs to the sink method `{sink_method}` are valid."""
            )
    elif category == "Prototype Pollution":
        if '"' in variable_detected or "=" in variable_detected:
            category_suggestion = "This is an informational finding."
            suppressable_finding = True
        elif sink_method in ("JSON.parse"):
            category_suggestion = f"""This is an informational finding since the sink method `{sink_method}` is safe by default."""
            suppressable_finding = True
        else:
            category_suggestion = f"""This could be an informational finding depending on the sink method `{sink_method}`. Look for the use of recursive functions that performs any object-level assignment."""
    elif category == "Timing Attack":
        if (
            '"' in variable_detected
            or "=" in variable_detected
            or not variable_detected
        ):
            category_suggestion = "This is an informational finding."
            suppressable_finding = True
        else:
            category_suggestion = f"""This finding is relevant only if the variable `{variable_detected}` holds security-sensitive value. Ignore this finding otherwise."""
    elif category == "Mail Injection":
        category_suggestion = f"""Ensure the variable `{variable_detected}` are encoded or sanitized before invoking the Email service."""
    elif category == "Deprecated Function Use":
        category_suggestion = f"Ensure the sink method `{sink_method}` is appropriate for use in this context."
    elif category in (
        "Security Best Practices",
        "Race Condition",
        "Security Misconfiguration",
        "Invalid Certificate Validation",
        "Error Handling",
    ):
        if variable_detected:
            category_suggestion = f"""This finding is based on best practices. Validate `{variable_detected}` for this context before invoking the sink method `{sink_method}`."""
        else:
            category_suggestion = "This finding is based on best practices. Please refer to the description for further information."
        suppressable_finding = True
    elif category in ("CRLF Injection", "Header Injection"):
        if variable_detected:
            category_suggestion = f"""Validate and ensure `{variable_detected}` does not contain any malicious input prior to invoking the sink `{sink_method}`."""
        else:
            category_suggestion = (
                "Please refer to the description for further information."
            )
    elif category == "Open Redirect":
        if variable_detected:
            category_suggestion = f"""Validate and ensure `{variable_detected}` does not contain any malicious URL or protocol prior to invoking the sink `{sink_method}`. Use an allowlist to verify the URL redirection domains."""
        else:
            category_suggestion = (
                "Please refer to the description for further information."
            )
    if "authorized" in ptags_set:
        suppressable_finding = True
        category_suggestion = f"""{category_suggestion}

**NOTE**: Proper Authorization check is performed in this flow. Consider reducing the severity of this finding.
"""
    return category_suggestion, suppressable_finding


def cohort_analysis(app_id, scan_id, source_cohorts, sink_cohorts, source_sink_cohorts):
    data_found = False
    table = Table(
        title=f"""Findings Similarity Analysis for {app_id}""",
        show_lines=True,
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
    )
    table.add_column("Category")
    table.add_column("Similar Data Flows")
    table.add_column("Finding ID", justify="right", style="cyan")
    for category, source_sink in source_sink_cohorts.items():
        for sshash, cohort_findings in source_sink.items():
            tmpA = sshash.split("|")
            if len(cohort_findings) > 1:
                deep_links = [
                    f"""[link=https://app.shiftleft.io/apps/{app_id}/vulnerabilities?scan={scan_id}&expanded=true&findingId={fid}]{fid}[/link]"""
                    for fid in cohort_findings
                ]
                table.add_row(
                    category,
                    f"""Start: {tmpA[0]}\nEnd: {tmpA[1]}""",
                    "\n".join(deep_links),
                )
                data_found = True
    if not data_found:
        for category, source_sink in sink_cohorts.items():
            for sink, cohort_findings in source_sink.items():
                if len(cohort_findings) > 1:
                    deep_links = [
                        f"""[link=https://app.shiftleft.io/apps/{app_id}/vulnerabilities?scan={scan_id}&expanded=true&findingId={fid}]{fid}[/link]"""
                        for fid in cohort_findings
                    ]
                    table.add_row(
                        category,
                        f"""End: {sink}""",
                        "\n".join(deep_links),
                    )
                    data_found = True
    if not data_found:
        for category, source_sink in source_cohorts.items():
            for source, cohort_findings in source_sink.items():
                if len(cohort_findings) > 1:
                    deep_links = [
                        f"""[link=https://app.shiftleft.io/apps/{app_id}/vulnerabilities?scan={scan_id}&expanded=true&findingId={fid}]{fid}[/link]"""
                        for fid in cohort_findings
                    ]
                    table.add_row(
                        category,
                        f"""Start: {source}""",
                        "\n".join(deep_links),
                    )
                    data_found = True
    if data_found:
        console.print("\n\n")
        console.print(table)


def find_best_oss_fix(
    org_id,
    app,
    scan,
    package_cves,
    source_dir,
    reachable_oss_count,
    unreachable_oss_count,
):
    data_found = False
    table = Table(
        title=f"""Best OSS Fix Suggestions for {app["name"]}""",
        show_lines=True,
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
    )
    table.add_column("Package")
    table.add_column("Reachable")
    table.add_column("Version", justify="right", max_width=40)
    table.add_column("CVE", max_width=40)
    table.add_column("Fix Version(s)", justify="right", max_width=40, style="cyan")
    for purl, cves in package_cves.items():
        fix_version = set()
        cveids = set()
        group = ""
        tmpA = purl.split("/")
        package_ver = tmpA[-1].split("@")
        if len(package_ver) != 2:
            continue
        pversion = package_ver[-1]
        package = package_ver[-2]
        if len(tmpA) > 2:
            group = tmpA[1]
        for cveobj in cves:
            reachability = cveobj.get("reachability")
            if not data_found:
                data_found = True
            cve_id = cveobj.get("cve")
            if not cve_id:
                cve_id = cveobj.get("oss_internal_id")
            cveids.add(cve_id)
            orig_fix_str = cveobj.get("fix", "").lower()
            orig_fix_wc = len(orig_fix_str.split(" "))
            # Ignore fix strings that do not contain versions
            if (
                orig_fix_str
                and "unfortunately" not in orig_fix_str
                and "maintained" not in orig_fix_str
                and orig_fix_wc < 10
            ):
                fixes_list = []
                fixes_str = (
                    orig_fix_str.replace("Upgrade to versions ", "")
                    .replace("Upgrade to ", "")
                    .split(" or ")[0]
                )
                if "," in fixes_str:
                    fixes_list = fixes_str.split(",")
                else:
                    fixes_list = [fixes_str]
                for new_fix_str in fixes_list:
                    if "." in new_fix_str:
                        new_fix_version = new_fix_str.strip()
                        fix_version.add(new_fix_version.split(" ")[-1])
        cveids = sorted(cveids, reverse=True)
        package_str = package
        if group:
            package_str = f"{group}/{package}"
        # If we have reachable oss findings then operate in reachable mode
        # If not report all critical and high oss vulnerabilities
        if reachable_oss_count > 0 and reachability != "reachable":
            continue
        try:
            fix_versions = sorted(fix_version, key=parse, reverse=True)
        except Exception:
            fix_versions = sorted(fix_version, reverse=True)
        # For long list of fix versions just show the first half
        if len(fix_versions) > 5:
            fix_versions = fix_versions[0 : math.ceil(len(fix_versions) / 2)]
        table.add_row(
            package_str,
            reachability.capitalize() if reachability == "reachable" else "",
            pversion,
            "\n".join(cveids),
            "\n".join(fix_versions),
        )
    if data_found:
        console.print("\n\n")
        console.print(table)


def troubleshoot_app(
    client, org_id, app_name, scan, findings, source_dir, annotated_findings
):
    ideas = []
    run_info = get_scan_run(client, org_id, scan, app_name)
    app_language = scan.get("language", "java")
    summary = run_info.get("summary", {})

    environment = summary.get("environment", {})
    sl_cmd = environment.get("cmd", [])
    tmp_data = environment.get("tmp", {})
    sl_cmd_str = ""
    build_machine = environment.get("machine", [])
    lang_args_used = False
    verbose_used = False
    remediation_used = False
    suppressable_count = 0
    check_methods_count = 0
    multiple_dep_projects_used = False
    for af in annotated_findings:
        if af.get("suppressable_finding"):
            suppressable_count += 1
        if af.get("check_methods"):
            check_methods_count += len(af.get("check_methods").split("\n"))
    if sl_cmd:
        sl_cmd_str = " ".join(sl_cmd)
        if "--tag" not in sl_cmd:
            ideas.append(
                """**CLI:** Pass the argument `--tag branch=name` to populate the branch name in the UI for this app."""
            )
        if "branch=" in sl_cmd:
            ideas.append(
                """**CLI:** Ensure the branch tag `--tag branch=name` is not empty to populate the branch name in the UI correctly."""
            )
        if "--cpg" in sl_cmd:
            ideas.append(
                "**CLI:** `--cpg` flag is no longer required for the `sl analyze` command."
            )
        if "--sca" in sl_cmd:
            ideas.append(
                "**CLI:** `--sca` flag is no longer required for the `sl analyze` command."
            )
        if "--dotnet-core" in sl_cmd:
            if "sl.exe" in sl_cmd_str:
                ideas.append(
                    "**CLI:** `--dotnet-core` flag is deprecated and no longer required for the `sl analyze` command on Windows."
                )
            else:
                ideas.append(
                    "**CLI:** `--dotnet-core` flag is deprecated and no longer required for the `sl analyze` command."
                )
        if "--oss-recursive" in sl_cmd:
            ideas.append(
                "**CLI:** `--oss-recursive` flag is set to true by default and is no longer required for the `sl analyze` command."
            )
        if "--force" in sl_cmd:
            ideas.append(
                "**CLI:** `--force` functionality is no longer available. This flag could be removed from the `sl analyze` command."
            )
        if "--remediation" in sl_cmd:
            remediation_used = True
        if "--" in sl_cmd:
            lang_args_used = True
        if "--verbose" in sl_cmd or "--trace-all" in sl_cmd:
            verbose_used = True
        if sl_cmd_str.count("--dep") > 1:
            multiple_dep_projects_used = True
            if app_language == "csharp":
                if ".sln" not in sl_cmd_str:
                    ideas.append(
                        "**CLI:** Consider scanning the solution file. To ignore test projects during analysis, pass `-- --ignore-tests` at the end of the `sl analyze` command."
                    )
                else:
                    ideas.append(
                        "**CLI:** `--dep` argument cannot be used while scanning a solution file. Please refer to https://docs.shiftleft.io/ngsast/analyzing-applications/c-sharp#apps-utilizing-msbuild-project-files to setup MSBuild project files for scanning this app."
                    )
            if app_language == "java":
                ideas.append(
                    "**CLI:** If the build target directory contains multiple jars, use `jar cvf app.jar -C $TARGET_DIR .` command to create a single larger jar for scanning."
                )
        if app_language == "java":
            if sl_cmd_str.count(".jar") > 1 and "--dep" not in sl_cmd_str:
                ideas.append(
                    "**CLI:** Only a single jar or war file could be passed to `sl analyze` for java applications.\nIf the build target directory contains multiple jars, use `jar cvf app.jar -C $TARGET_DIR .` command to create a single larger jar for scanning."
                )
            if "--vcs-prefix-correction" not in sl_cmd_str:
                lang = (
                    "scala"
                    if ("scala" in sl_cmd_str or "sbt" in sl_cmd_str)
                    else "java"
                )
                if app_language == "java" and "assembly" in sl_cmd_str:
                    lang = "scala"
                ideas.append(
                    f"""**CLI:** Pass the argument `--vcs-prefix-correction "*=src/main/{lang}"` to make the Source Code View work correctly in the UI."""
                )
        if sl_cmd_str.count("--wait") > 1:
            ideas.append("**CLI:** `--wait` argument is specified more than once.")
    os_release = environment.get("os-release", {}).get("os-release", "").lower()
    if os_release:
        if "ubuntu 18.04" in os_release:
            if app_language in (
                "python",
                "pythonsrc",
                "terraform_hcl",
                "terraform",
                "aws",
                "azure",
                "kubernetes",
            ):
                ideas.append(
                    "**OS:** Build machine is using `Ubuntu 18.04` which is not supported for this language. Upgrade to `Ubuntu 20.04` or higher."
                )
            else:
                ideas.append(
                    "**OS:** Build machine is using `Ubuntu 18.04`. To improve performance, upgrade to `Ubuntu 20.04` or higher."
                )
        elif "ubuntu 20.04" in os_release:
            if app_language in ("javasrc", "javascriptsrc", "pythonsrc", "csharp"):
                ideas.append(
                    "**OS:** Build machine is using `Ubuntu 20.04` which is not recommended for this language. Upgrade to `Ubuntu 22.04` or higher."
                )
        if "alpine" in os_release:
            if app_language in (
                "python",
                "pythonsrc",
                "terraform_hcl",
                "terraform",
                "aws",
                "azure",
                "kubernetes",
            ):
                ideas.append(
                    "**OS:** Build machine appears to be using `Alpine Linux` which is not recommended for this language. Consider switching to a supported flavour of linux such as Ubuntu or Debian."
                )
    sizes = summary.get("sizes")
    size_based_reco = False
    perf_based_reco = False
    uploadRequest = summary.get("upload-request", {})
    metadata_artifact = uploadRequest.get("metadata_artifact", [])
    container_sbom_found = False
    sca_sbom_found = False
    for mart in metadata_artifact:
        if mart.get("metadata_file_name", ""):
            if "container_bom.xml" in mart.get("metadata_file_name"):
                container_sbom_found = True
            elif "-bom.xml" in mart.get("metadata_file_name"):
                sca_sbom_found = True
            elif not remediation_used and "remediation" in mart.get(
                "metadata_file_name"
            ):
                remediation_used = True
    low_findings_count = False
    if sizes:
        files = sizes.get("files", 0)
        lines = sizes.get("lines", 0)
        binsize = sizes.get("binsize", 0)
        low_findings_count = (
            lines
            and int(lines) > 2000
            and len(findings) < 10
            and (findings and lines and len(findings) < math.ceil(int(lines) / 1000))
            and not remediation_used
        )
        if not low_findings_count and binsize:
            low_findings_count = len(findings) < 10 and not remediation_used
        if app_language == "java" and binsize and int(binsize) < 4000:
            ideas.append(
                "**CLI:** Pass the .war file or a uber jar to get better results for Java applications."
            )
            ideas.append(
                "**CLI:** If the build target directory contains multiple jars, use `jar cvf app.jar -C $TARGET_DIR .` command to create a single larger jar for scanning."
            )
            size_based_reco = True
        scan_duration_ms = summary.get("scan_duration_ms", 0)
        if scan_duration_ms > 3 * 60 * 1000:
            size_suggestion = ""
            if int(binsize) > 50000 and app_language == "java":
                size_suggestion = "Try scanning the jar file containing only the custom code instead of a uber jar or a war file.\nFor apps containing many libraries, please contact Qwiet.AI support for further optimizations ideas."
            if files:
                if app_language in ("js", "ts", "javascript", "typescript"):
                    if "--exclude" not in sl_cmd_str:
                        size_suggestion = "Pass the argument `-- --exclude <path-1>,<path-2>,...` to exclude specified directories during code analysis."
                    else:
                        size_suggestion = "Ensure the application is not built prior to invoking Qwiet.AI."
                if app_language == "python":
                    size_suggestion = "Pass the argument `-- --ignore-paths [<ignore_path_1>] [<ignore_path_2>]` to ignore specified paths during code analysis."
                if app_language == "csharp":
                    if ".csproj" not in sl_cmd_str:
                        size_suggestion = "Scan the required .csproj files instead of the solution to improve speed."
                    if ".sln" in sl_cmd_str and "--ignore-tests" not in sl_cmd_str:
                        size_suggestion = "Pass the argument `-- --ignore-tests` to ignore test projects during code analysis."
                if app_language == "go" and "./..." in sl_cmd_str:
                    size_suggestion = "Scan only the required module using `.` or `module name` syntax."
            if size_suggestion:
                perf_based_reco = True
                ideas.append(
                    f"**PERF:** Scan time was over {math.floor(scan_duration_ms / (60 * 1000))} mins.\n{size_suggestion}"
                )
                if app_language in ("java", "javasrc"):
                    ideas.append(
                        "**PERF:** Customize the sensitive data dictionary or consider disabling it (if permitted by AppSec) to improve performance."
                    )
                    ideas.append(
                        """**PERF:** Set these two environment variables to increase the memory available for CPG generation. `export SL_CPG_OPTS="-J-Xms2g -J-Xmx7g"` and `export SHIFTLEFT_JAVA_OPTS="-Xms2g -Xmx7g"`"""
                    )
            if "--wait" in sl_cmd_str:
                ideas.append(
                    "**PERF:** Remove `--wait` argument and any subsequent invocation of `sl check-analysis` to perform scans in asynchronous mode."
                )
        if app_language in ("js", "ts", "javascript", "typescript", "python", "go"):
            low_findings_count = (
                lines
                and int(lines) > 2000
                and len(findings) < math.ceil(int(lines) / 2000)
            )
        if files and int(files) < 10:
            ideas.append(f"**APP:** This is a small app with only `{files}` files.")
            size_based_reco = True
        elif lines and int(lines) < 2000:
            ideas.append(
                f"**APP:** This is a small app with only `{lines}` lines of code."
            )
            size_based_reco = True
        if low_findings_count:
            if app_language == "go" and "./..." not in sl_cmd:
                ideas.append(
                    "Pass `./...` to scan this go app by including all the sub-projects."
                )
            if (
                app_language == "csharp"
                and not verbose_used
                and not multiple_dep_projects_used
            ):
                ideas.append(
                    "Ensure the solution is restored or built successfully prior to invoking Qwiet.AI."
                )
                if ".sln" not in sl_cmd_str:
                    ideas.append(
                        "Try scanning the solution instead of a specific csproj."
                    )
            if app_language == "python" and len(findings) < 5:
                if not verbose_used:
                    ideas.append(
                        "Ensure the project dependencies are installed with `pip install` command prior to invoking Qwiet.AI."
                    )
                ideas.append(
                    "To include additional python module search paths in the analysis, pass `-- --extra-sys-paths [<path>]`."
                )
                ideas.append(
                    "For monorepos, scan the individual apps or microservices separately using multiple invocation of `sl analyze` command. Pass `--tag app.group=groupname` to the `sl analyze` command to group the individual apps in the UI."
                )
            if app_language == "java" and int(binsize) < 15000:
                ideas.append(
                    "Pass the .war file or a uber jar to get better results for Java applications."
                )
                ideas.append(
                    "If the build target directory contains multiple jars, use `jar cvf app.jar -C $TARGET_DIR .` command to create a single larger jar for scanning."
                )
            if app_language in ("js", "ts", "javascript", "typescript"):
                if "ui" in app_name:
                    ideas.append(
                        "**UI:** Ensure only applications and not UI toolkits are scanned with Qwiet.AI."
                    )
    if (
        build_machine
        and app_language in ("java", "javasrc", "csharp", "python", "pythonsrc", "go")
        and not size_based_reco
        and perf_based_reco
    ):
        num_cpu = build_machine.get("cpu", {}).get("num", "")
        memory_total = build_machine.get("memory", {}).get("total", "")
        if num_cpu and int(num_cpu) < 4:
            ideas.append(
                f"**CI:** Ensure the build machine has a minimum of 4 CPU cores to reduce CPG generation time. Found only {num_cpu} cores."
            )
            if app_language == "java":
                ideas.append(
                    "Alternatively, to reduce scan time, pass the argument `--no-cpg` (if permitted by your AppSec team), to generate CPG in the Qwiet.AI cloud."
                )
        if memory_total and int(memory_total) < 4096:
            ideas.append(
                f"**CI:** Ensure the build machine has a minimum of 4096 MB RAM to reduce CPG generation time. Found only {memory_total} MB."
            )
    methods = summary.get("methods")
    if methods:
        namespaces = methods.get("namespaces", {})
        unannotated = methods.get("unannotated", {})
        filtered_namespaces = set()
        filtered_unannotated = set()
        library_reco = False
        if unannotated and low_findings_count and app_language in ("java", "javasrc"):
            # There are annotations but still low findings count. Check if we might be missing something
            for uk, uv in unannotated.items():
                for key_framework in (
                    "google.",
                    "aws",
                    "azure",
                    "sql",
                    "cloud",
                    "framework",
                ):
                    if key_framework in uk:
                        filtered_namespaces.add(uk)
                        filtered_unannotated.update(uv)
            if filtered_namespaces:
                if len(filtered_namespaces) > 4:
                    filtered_namespaces = filtered_namespaces[:4]
                ideas.append(
                    f"""**SUPPORT:** This app might be using libraries that are not supported yet. Please contact Qwiet.AI support to manually review this app.\nSome namespaces to review: {", ".join(filtered_namespaces)}"""
                )
    if methods and not size_based_reco:
        ios = methods.get("ios", 0)
        sinks = methods.get("sinks", 0)
        total = methods.get("total", 0)
        sources = methods.get("sources", 0)
        if summary.get("isLibrary"):
            if not sources and sinks:
                library_reco = True
                ideas.append(
                    "**APP:** This repo could be a library. Ensure only applications are scanned with Qwiet.AI."
                )
            if ("lib" in app_name or "common" in app_name) and not sinks:
                library_reco = True
                ideas.append(
                    "**APP:** This repo is a library. Ensure only applications are scanned with Qwiet.AI."
                )
        if (
            not ios
            or not int(ios)
            or not sources
            or not int(sources)
            or not sinks
            or not int(sinks)
        ):
            if not multiple_dep_projects_used:
                if not library_reco and metadata_artifact:
                    ideas.append(
                        "**SUPPORT:** This app might be using libraries that are not supported yet. Please contact Qwiet.AI support to manually review this app."
                    )
                elif "lib" not in app_name and metadata_artifact:
                    ideas.append(
                        "**SUPPORT:** Alternatively, this app might be using private dependencies or third-party libraries that are not supported yet. Please contact Qwiet.AI support to manually review this app."
                    )
        if total and int(total) < 20:
            ideas.append(f"This is a small app with only {total} methods.")
    token = summary.get("token")
    if token and token.get("name", "") == "Personal Access":
        ideas.append(
            f"""**TOKEN:** Use a CI integration token to scan apps with Qwiet.AI. Currently scanned with `{token.get("owner")}'s` personal access token."""
        )
    if not sca_sbom_found and app_language not in (
        "terraform_hcl",
        "terraform",
        "aws",
        "azure",
        "kubernetes",
        "unknown",
    ):
        sbom_idea = ""
        if app_language == ("java", "javasrc"):
            sbom_idea = "Ensure the entire source directory and build tools such as maven, gradle or sbt are available in the build step running Qwiet.AI."
            if "--oss-project-dir" not in sl_cmd_str:
                sbom_idea += " Use the argument `--oss-project-dir <source path>` to specify the source directory explicitly."
            if "build" in sl_cmd_str:
                sbom_idea += "\nFor some gradle multi-module project, setting the environment variable GRADLE_MULTI_PROJECT_MODE to true might help."
            elif "target" in sl_cmd_str:
                sbom_idea += "\nTry running the maven command, `mvn org.cyclonedx:cyclonedx-maven-plugin:2.7.2:makeAggregateBom -DoutputName=bom` before sl analyze to troubleshoot further."
                sbom_idea += "\nIf additional arguments are found to be required for maven, then set those via the environment variable `MVN_ARGS`"
        if app_language in ("js", "ts", "javascript", "typescript", "javascriptsrc"):
            sbom_idea = "Ensure the lock files such as package-lock.json or yarn.lock or pnpm-lock.yaml are present. If required perform npm or yarn install to generate the lock files prior to invoking Qwiet.AI."
        if app_language in ("python", "pythonsrc"):
            sbom_idea = "Ensure the lock files such as requirements.txt or Pipfile.lock or Poetry.lock are present. If required run `pip freeze > requirements.txt` to generate a requirements file prior to invoking Qwiet.AI."
        if app_language == "go":
            sbom_idea = "Ensure the package manifest files such as go.mod or go.sum or Gopkg.lock are present in the repo."
        if app_language == "csharp":
            sbom_idea = "Ensure the solution is restored or built successfully prior to invoking Qwiet.AI."
        if sbom_idea:
            ideas.append(
                f"""**iSCA:** Software Bill-of-Materials (SBoM) was not generated correctly for this project.\n{sbom_idea}"""
            )
    if suppressable_count or check_methods_count:
        if remediation_used:
            ideas.append(
                """**Remediation:** Review this best fix report and update the existing remediation config to suppress additional findings."""
            )
        else:
            ideas.append(
                """**Remediation:** Review this best fix report and create a remediation config to suppress additional findings."""
            )
    if ideas:
        console.print("\n")
        console.print(
            Panel(
                Markdown(MD_LIST_MARKER + MD_LIST_MARKER.join(ideas)),
                title=f"Scan Improvements for {app_name} ({app_language})",
                expand=False,
            )
        )
        if perf_based_reco:
            console.print(f"Internal id for this scan: {scan.get('internal_id')}\n")


def file_locations_tree(
    internal_id,
    category,
    files_loc_list,
    files_method_list,
    http_routes,
    tracked_list,
    full_path_prefix,
):
    conclusion_name = internal_id.split("/")[0]
    first_route = None
    http_routes = [r for r in http_routes if r != "*"]
    if http_routes and len(http_routes):
        first_route = http_routes[0]
    tree = Tree(
        f"{category} ({first_route if first_route and first_route != '*' else conclusion_name})",
        guide_style="bold bright_blue",
    )
    i = 0
    first_var = "Parameter"
    last_var = "Parameter"
    if tracked_list:
        first_var = tracked_list[0]
        if len(tracked_list) > 1:
            last_var = tracked_list[-1]
    for fm in files_method_list:
        if i == 1:
            tree.add(
                f"[bold green]// Validate {first_var}\nvalidate{first_var[0].upper() + first_var[1:]}()"
            )
        if i > 1 and i == len(files_method_list) - 1:
            tree.add(
                f"[bold green]// Additional checks for {last_var}\ncheck{last_var[0].upper() + last_var[1:]}()"
            )
        tree.add(fm)
        i = i + 1
    # for fl in files_loc_list:
    #     aloc = f"[link={to_local_path(full_path_prefix, fl)}]{escape(fl)}[/link]"
    #     tree.add(aloc)
    return tree


def num_to_emoji(c):
    if not c:
        return "-"
    return str(c)


def print_scan_stats(scan, counts):
    if not scan or not counts:
        return
    message = ""
    files_count = 0
    loc_count = 0
    deps_count = 0
    oss_unreachable_count = 0
    oss_reachable_count = 0
    ratings_counts_dict = defaultdict(int)
    oss_ratings_counts_dict = defaultdict(int)
    container_ratings_counts_dict = defaultdict(int)
    source_counts_dict = defaultdict(int)
    sink_counts_dict = defaultdict(int)
    owasp_counts_dict = defaultdict(int)
    owasp_empty = True
    ratings_empty = True
    stats = scan.get("stats", {})
    if not stats:
        return
    if stats.get("data"):
        data = scan.get("stats", {}).get("data")
        for d in data:
            if d.get("key") == "Code":
                code_data = d.get("data")
                for acd in code_data:
                    # Files count can be found directly in count or nested inside data
                    if acd.get("key") == "File":
                        if acd.get("count"):
                            files_count = acd.get("count")
                        if acd.get("data"):
                            for fd in acd.get("data"):
                                if fd.get("key") == "Internal":
                                    files_count = fd.get("count")
                    # Qwiet engineers cannot make up their mind on the key
                    if acd.get("key") in ("Loc", "Lines of code") and acd.get("count"):
                        loc_count = acd.get("count")
            if d.get("key") == "OSS":
                oss_data = d.get("data")
                for osd in oss_data:
                    if osd.get("key") == "Dependencies":
                        deps_count = osd.get("count")
    for c in counts:
        if c.get("finding_type") == "vuln":
            if c.get("key") == "cvss_31_severity_rating":
                ratings_counts_dict[c.get("value")] = c.get("count")
                ratings_empty = False
            if c.get("key") == "owasp_2021_category":
                owasp_counts_dict[c.get("value")] = c.get("count")
                owasp_empty = False
            if c.get("key") == "source_method":
                source_counts_dict[c.get("value")] = c.get("count")
            if c.get("key") == "sink_method":
                sink_counts_dict[c.get("value")] = c.get("count")
        if c.get("finding_type") == "oss_vuln":
            if c.get("key") == "cvss_31_severity_rating":
                oss_ratings_counts_dict[c.get("value")] = c.get("count")
            if c.get("key") == "reachability":
                if c.get("value") == "unreachable":
                    oss_unreachable_count = c.get("count")
                if c.get("value") == "reachable":
                    oss_reachable_count = c.get("count")
        if c.get("finding_type") == "container":
            if c.get("key") == "cvss_31_severity_rating":
                container_ratings_counts_dict[c.get("value")] = c.get("count")
    critical_high_count = ratings_counts_dict["critical"] + ratings_counts_dict["high"]
    message += f"""\nBestfix from Qwiet.AI analyzed scan #{scan["id"]} for the {scan["language"]} app {scan["app"]} on {scan["started_at"].split("T")[0]}."""
    if files_count:
        message += f""" {files_count} files were analyzed during this scan"""
    elif loc_count:
        message += f""" {loc_count} lines of code were analyzed during this scan"""
    if critical_high_count:
        message += (
            f" resulting in {critical_high_count} critical and high vulnerabilities. "
        )
    else:
        message += ", and no critical or high vulnerabilities were found. "
    if deps_count:
        message += f"{deps_count} open-source dependencies were also identified"
        if oss_reachable_count:
            message += f" in which {oss_reachable_count} vulnerabilities were found."
        else:
            message += "."
    message += " Use the information in this report to mitigate the open-source and custom code vulnerabilities and to improve the scan performance."
    console.print("\n")
    console.print(Markdown("## Executive Summary"))
    console.print(message)
    if not owasp_empty:
        console.print("\n\n")
        table = Table(
            title=f"""OWASP Summary""",
            show_lines=True,
            box=box.DOUBLE_EDGE,
            header_style="bold green",
            expand=False,
        )
        table.add_column("Category")
        table.add_column("Count", justify="right", style="cyan")
        # OWASP Table needs a fixed ordering
        for col in (
            "a01-broken-access-control",
            "a02-cryptographic-failures",
            "a03-injection",
            "a04-insecure-design",
            "a05-security-misconfiguration",
            "a06-vulnerable-and-outdated-components",
            "a07-identification-and-authentication-failures",
            "a08-software-and-data-integrity-failures",
            "a09-security-logging-and-monitoring-failures",
            "a10-server-side-request-forgery-(ssrf)",
        ):
            table.add_row(col, num_to_emoji(owasp_counts_dict[col]))
        console.print(table)
    if not ratings_empty:
        console.print("\n")
        table = Table(
            title=f"""CVSS Ratings Summary""",
            show_lines=True,
            box=box.DOUBLE_EDGE,
            header_style="bold green",
            expand=False,
        )
        table.add_column("Rating")
        table.add_column("Count", justify="right", style="cyan")
        for col in ("critical", "high", "medium", "low"):
            table.add_row(col, num_to_emoji(ratings_counts_dict[col]))
        console.print(table)


def find_best_fix(org_id, app, scan, findings, counts, source_dir):
    annotated_findings = []
    if not findings:
        return annotated_findings
    data_found = False
    table = Table(
        title=f"""Best Fix Suggestions for {app["name"]}""",
        show_lines=True,
        box=box.DOUBLE_EDGE,
        header_style="bold green",
        expand=True,
    )
    table.add_column("ID", justify="right", style="cyan")
    table.add_column("Severity")
    if CI_MODE:
        table.add_column("Category")
    table.add_column(
        "Remediated Flow",
        overflow="fold",
        max_width=160 if "win32" in sys.platform and not CI_MODE else 120,
    )
    # table.add_column("Code Snippet", overflow="fold", min_width=10)
    table.add_column("Comment", overflow="fold")
    source_cohorts = defaultdict(dict)
    sink_cohorts = defaultdict(dict)
    source_sink_cohorts = defaultdict(dict)
    package_cves = defaultdict(list)
    app_language = scan.get("language", "java")
    reachable_oss_count = 0
    unreachable_oss_count = 0
    for afinding in findings:
        # Skip ignored and fixed findings
        if afinding.get("status") in ("ignore", "ignored", "fixed"):
            continue
        category = afinding.get("category")
        # Ignore Sensitive Data Leaks, Sensitive Data Usage and Log Forging for now.
        if "Sensitive" in category or "Log" in category:
            continue
        files_loc_list = []
        files_method_list = []
        files_method_simple_list = []
        tracked_list = []
        snippet_list = []
        source_method = ""
        sink_method = ""
        cvss_31_severity_rating = ""
        cvss_score = ""
        reachability = ""
        details = afinding.get("details", {})
        source_method = details.get("source_method", "")
        sink_method = details.get("sink_method", "")
        # Simplify method names
        if source_method and app_language not in (
            "js",
            "javascript",
            "ts",
            "typescript",
        ):
            source_method = source_method.split(":")[0]
        if sink_method and app_language not in ("js", "javascript", "ts", "typescript"):
            sink_method = sink_method.split(":")[0]
        tags = afinding.get("tags")
        methods_list = []
        check_methods = set()
        http_routes = set()
        event_routes = set()
        ptags_set = set()
        mtags_set = set()
        package_url = ""
        cve = ""
        oss_internal_id = ""
        if tags:
            for tag in tags:
                if tag.get("key") == "cvss_31_severity_rating":
                    cvss_31_severity_rating = tag.get("value")
                elif tag.get("key") == "cvss_score":
                    cvss_score = tag.get("value")
                elif tag.get("key") == "reachability":
                    reachability = tag.get("value")
                elif tag.get("key") == "package_url":
                    package_url = tag.get("value")
                elif tag.get("key") == "cve":
                    cve = tag.get("value")
                elif tag.get("key") == "oss_internal_id":
                    oss_internal_id = tag.get("value")
        # For old scans, details block might be empty.
        # We go old school and iterate all dataflows
        dfobj = {}
        if details.get("dataflow"):
            dfobj = details.get("dataflow")
        dataflows = dfobj.get("list", [])
        for df in dataflows:
            location = df.get("location", {})
            file_name = location.get("file_name")
            method_name = location.get("method_name")
            # Simplify method names
            if method_name:
                method_name = method_name.split(":")[0]
            short_method_name = location.get("short_method_name")
            fmt_short_method_name = short_method_name
            parameter_tags = df.get("parameter_tags", [])
            ptags = [
                pt.get("value")
                for pt in parameter_tags
                if pt.get("key", "") in (9, 31) and pt.get("value")
            ]
            if ptags:
                ptags_set.update(ptags)
            # Try hard to find http and event routes
            if not http_routes:
                for all_rt in config.all_routes_tags:
                    if all_rt in ptags:
                        http_routes.add("*")
                        break
            if not event_routes:
                for all_et in config.all_events_tags:
                    if all_et in ptags:
                        event_routes.add("*")
                        break
            if file_name == "N/A" or not location.get("line_number"):
                continue
            # Skip getter/setter methods in csharp
            if ".cs" in file_name and (
                "get_" in short_method_name or "set_" in short_method_name
            ):
                continue
            # Skip vendor and stdlib for go
            if ".go" in file_name and (
                file_name.startswith("vendor") or file_name.startswith("/")
            ):
                continue
            # Skip anonymous methods in scala
            if ".scala" in file_name and short_method_name.startswith("$anon"):
                continue
            variableInfo = df.get("variable_info", {})
            symbol = ""
            if variableInfo.get("variable"):
                variableInfo = variableInfo.get("variable")
            if variableInfo.get("Variable"):
                variableInfo = variableInfo.get("Variable")
            # Identify http routes
            method_tags = df.get("method_tags", [])
            mtags = [
                mt.get("value")
                for mt in method_tags
                if mt.get("key", "") in ("EXPOSED_METHOD_ROUTE", 30) and mt.get("value")
            ]
            route_value = mtags[0] if mtags else None
            if mtags:
                mtags_set.update(mtags)
            if route_value:
                http_routes.add(route_value)
            # Look for middlewares, filters that can operate on all routes
            lower_file_name = file_name.lower()
            if (
                not http_routes
                and "filter" in lower_file_name
                or "middleware" in lower_file_name
                or "route" in lower_file_name
                or "controller" in lower_file_name
                or "service" in lower_file_name
            ):
                http_routes.add("*")
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
                if member and member.get("symbol"):
                    msymbol = member.get("symbol")
                    if (
                        "(" in msymbol
                        or ")" in msymbol
                        or "{" in msymbol
                        or " " in msymbol
                    ):
                        if msymbol not in snippet_list:
                            snippet_list.append(msymbol)
                    else:
                        symbol = msymbol.split(".")[-1]
                if local and local.get("symbol"):
                    symbol = local.get("symbol")
                if (
                    symbol
                    and symbol not in tracked_list
                    and "____obj" not in symbol
                    and "_tmp_" not in symbol
                    and not symbol.endswith("_0")
                    and not symbol.startswith("$")
                    and not symbol.endswith("DTO")
                    and symbol not in ("this", "req", "res", "p1", "env")
                ):
                    if "(" in symbol or ")" in symbol or "{" in symbol or " " in symbol:
                        if symbol not in snippet_list:
                            snippet_list.append(symbol)
                    elif ".cs" in location.get("file_name"):
                        if "Dto" not in symbol and symbol not in tracked_list:
                            tracked_list.append(symbol)
                    else:
                        cleaned_symbol = symbol.replace("val$", "")
                        # Clean $ suffixed variables in scala
                        if file_name.endswith(".scala") and "$" in cleaned_symbol:
                            cleaned_symbol = cleaned_symbol.split("$")[0]
                        if cleaned_symbol not in tracked_list:
                            tracked_list.append(cleaned_symbol)
            if short_method_name and "empty" not in short_method_name:
                if "$" in short_method_name and app_language in ("java", "javasrc"):
                    short_method_name = short_method_name.replace("lambda$", "")
                    short_method_name = short_method_name.split("$")[0]
                # For JavaScript/TypeScript short method name is mostly anonymous
                if "anonymous" in short_method_name:
                    short_method_name = (
                        method_name.split(":anonymous")[0]
                        .split("::")[-1]
                        .split(":")[-1]
                    )
                    if short_method_name == "program":
                        short_method_name = method_name.split("::")[0] + ":program"
                elif "_callee" in short_method_name:
                    short_method_name = (
                        method_name.split(":_callee")[0].split("::")[-1].split(":")[-1]
                    )
                methods_list.append(short_method_name)
                fmt_short_method_name = short_method_name
                for check_labels in config.check_labels_list:
                    if check_labels in short_method_name.lower():
                        check_methods.add(method_name)
                        fmt_short_method_name = (
                            f"[dim green]{short_method_name}[/dim green]"
                        )
                # Methods that start with is are usually validation methods
                if re.match(r"^is[_A-Z]", short_method_name):
                    check_methods.add(method_name)
            if not source_method:
                source_method = (
                    f'{location.get("file_name")}:{location.get("line_number")}'
                )
            loc_line = f'{location.get("file_name")}:{location.get("line_number")}'
            last_tracked = ""
            if tracked_list:
                last_tracked = tracked_list[-1]
            method_line = f'[dim]{location.get("file_name")}:{location.get("line_number")}[/dim]  {fmt_short_method_name}( [bold red]{last_tracked}[/bold red] )'
            method_simple_line = f'[dim]{location.get("file_name")}  {short_method_name}( [bold red]{last_tracked}[/bold red] )'
            # Remove erroneous CI prefixes
            for tci in config.trimmable_ci_paths:
                loc_line = loc_line.replace(tci, "")
                method_line = method_line.replace(tci, "")
            loc_line = unquote(loc_line)
            method_line = unquote(method_line)
            if loc_line not in files_loc_list:
                files_loc_list.append(loc_line)
            if method_simple_line not in files_method_simple_list:
                files_method_list.append(method_line)
                files_method_simple_list.append(method_simple_line)
        if dataflows and dataflows[-1]:
            sink = dataflows[-1].get("location", {})
            if sink and not sink_method:
                sink_method = f'{sink.get("file_name")}:{sink.get("line_number")}'
        ###########
        if afinding.get("type") == "vuln":
            methods_list = methods_list
            check_methods = list(check_methods)
            last_location = ""
            first_location = ""
            if files_loc_list:
                last_location = files_loc_list[-1]
                first_location = files_loc_list[0]
            # Ignore html files
            if "html" in last_location and len(files_loc_list) > 2:
                last_location = files_loc_list[-2]
            if first_location and not source_cohorts[category].get(first_location):
                source_cohorts[category][first_location] = []
            if last_location and not sink_cohorts[category].get(last_location):
                sink_cohorts[category][last_location] = []
            if (
                first_location
                and last_location
                and not source_sink_cohorts[category].get(
                    f"{first_location}|{last_location}"
                )
            ):
                source_sink_cohorts[category][f"{first_location}|{last_location}"] = []
            # Identify cohorts
            if first_location:
                source_cohorts[category][first_location].append(afinding.get("id"))
            if last_location:
                sink_cohorts[category][last_location].append(afinding.get("id"))
            if first_location and last_location:
                source_sink_cohorts[category][
                    f"{first_location}|{last_location}"
                ].append(afinding.get("id"))
            tmpA = last_location.split(":")
            tmpB = first_location.split(":")
            last_location_lineno = 1
            first_location_lineno = 1
            if tmpA[-1]:
                last_location_lineno = int(tmpA[-1])
            if len(tmpA) == 2:
                last_location_fname = tmpA[0]
            else:
                last_location_fname = last_location.replace(
                    f":{last_location_lineno}", ""
                )
            if tmpB[-1]:
                first_location_lineno = int(tmpB[-1])
            if len(tmpB) == 2:
                first_location_fname = tmpB[0]
            else:
                first_location_fname = first_location.replace(
                    f":{first_location_lineno}", ""
                )
            code_snippet, variable_detected, full_path = get_code(
                source_dir, app, last_location_fname, last_location_lineno, tracked_list
            )
            full_path_prefix = ""
            if full_path:
                full_path_prefix = full_path.replace(last_location_fname, "")
            # Arrive at a best fix
            best_fix = ""
            location_suggestion = ""
            if last_location_fname:
                location_suggestion = f"- Before or at line {last_location_lineno} in {last_location_fname}"
            category_suggestion = ""
            suppressable_finding = False
            if (
                first_location_fname != last_location_fname
                or last_location_lineno - first_location_lineno > 3
            ):
                location_suggestion = (
                    location_suggestion
                    + f"\n- After line {first_location_lineno} in {first_location_fname}"
                )
            http_routes = list(http_routes)
            event_routes = list(event_routes)
            source_variable = ""
            if tracked_list:
                source_variable = tracked_list[0]
            if (
                source_method == sink_method or (not http_routes and not event_routes)
            ) and "lambda" not in source_method:
                if not variable_detected and tracked_list:
                    variable_detected = tracked_list[-1]
                category_suggestion, suppressable_finding = get_category_suggestion(
                    category,
                    variable_detected,
                    source_method,
                    sink_method,
                    ptags_set,
                    mtags_set,
                )
                taint_suggestion = ""
                if (
                    not http_routes
                    and not event_routes
                    and "lambda" not in source_method
                    and variable_detected not in ("event", "ctx", "request", "headers")
                    and source_variable not in ("event", "ctx", "request", "headers")
                    and app_language not in ("python")
                    and not last_location_fname.endswith(".scala")
                ):
                    taint_suggestion = (
                        (
                            "There are no attacker-reachable HTTP routes for this finding."
                        )
                        if not suppressable_finding
                        else ""
                    )
                    if not category_suggestion and variable_detected:
                        taint_suggestion += (
                            f" **Taint:** Variable `{variable_detected}`."
                        )
                elif variable_detected:
                    taint_suggestion = f"**Taint:** Variable `{variable_detected}`."
                preface_text = (
                    "This is likely a security best practices or an informational finding."
                    if suppressable_finding
                    else ""
                )
                if snippet_list:
                    preface_text = "This is a security best practices type finding."
                best_fix = f"""{preface_text}
{taint_suggestion}
{category_suggestion}

**Suppression:**\n
Specify the sink method in your remediation config to suppress this finding.\n
- {sink_method if "<operator>" not in sink_method else "Parent method of " + sink_method}

"""
            elif variable_detected:
                category_suggestion, suppressable_finding = get_category_suggestion(
                    category,
                    variable_detected,
                    source_method,
                    sink_method,
                    ptags_set,
                    mtags_set,
                )
                best_fix = f"""**Taint:** Parameter `{variable_detected}` in the method `{methods_list[-1]}`\n
{category_suggestion if category_suggestion else f"Validate or sanitize the parameter `{variable_detected}` before invoking the sink `{sink_method}`"}
"""
            elif tracked_list:
                # No variable detected but taint list available
                variable_detected = tracked_list[-1]
                Parameter_str = "Parameter"
                if len(tracked_list) > 4:
                    variable_detected = (
                        f"{tracked_list[0]}, {tracked_list[-2]} and {tracked_list[-1]}"
                    )
                    Parameter_str = "Variables"
                category_suggestion, suppressable_finding = get_category_suggestion(
                    category,
                    variable_detected,
                    source_method,
                    sink_method,
                    ptags_set,
                    mtags_set,
                )
                best_fix = f"""**Taint:** {Parameter_str} `{variable_detected}` in the method `{methods_list[-1]}`\n
{category_suggestion if category_suggestion else f"Validate or sanitize the {Parameter_str} `{variable_detected}` before invoking the sink `{sink_method}`"}
"""
            if check_methods:
                if (
                    not variable_detected
                    and not tracked_list
                    and not category_suggestion
                ):
                    best_fix = f"""Validate or sanitize user provided input before invoking the sink method `{sink_method}`
"""
                if not suppressable_finding:
                    best_fix = (
                        best_fix
                        + f"""
**Remediation suggestions:**\n
Include these detected CHECK methods in your remediation config to suppress this finding.\n
- {MD_LIST_MARKER.join(check_methods)}
"""
                    )
            ignorables_list = find_ignorables(
                app_language, last_location_fname, files_loc_list
            )
            ignorables_suggestion = ""
            if ignorables_list:
                if app_language == "csharp":
                    ignorables_suggestion = """To ignore test projects during analysis, pass `-- --ignore-tests` at the end of the `sl analyze` command."""
                if app_language in ("js", "javascript", "ts", "typescript"):
                    ignorables_suggestion = """To ignore unit tests, samples and built artefacts during analysis, pass `-- --exclude <path-1>,<path-2>,...` at the end of the `sl analyze` command."""
                if app_language == "python":
                    ignorables_suggestion = """To ignore specific directory from analysis, pass `-- --ignore-paths [<ignore_path_1>] [<ignore_path_2>]` at the end of the `sl analyze` command."""
            # Fallback
            if not best_fix:
                if app_language in ("java", "javasrc", "scala", "csharp"):
                    best_fix = "No fix suggestion available for this finding."
                else:
                    best_fix = f"""{"This is likely a security best practices type finding." if app_language in ("js", "python") else "This is an informational finding."}

**Remediation suggestions:**\n
Specify the sink method in your remediation config to suppress this finding.\n
- {sink_method}

"""
            # Show code snippet if available
            if snippet_list and not code_snippet:
                code_snippet = snippet_list[-1]
            # Any files to ignore
            if ignorables_suggestion:
                best_fix = (
                    best_fix
                    + f"""
**Scan suggestions:**\n
{ignorables_suggestion}
"""
                )
            deep_link = f"""https://app.shiftleft.io/apps/{app["id"]}/vulnerabilities?scan={scan.get("id")}&expanded=true&findingId={afinding.get("id")}"""
            comment_str = "//"
            if app_language == "python":
                comment_str = "#"
            data_found = True
            fmt_code_snippet = code_snippet
            if not CI_MODE and code_snippet:
                fmt_code_snippet = Syntax(
                    f"{comment_str} {last_location_fname}\n\n" + code_snippet,
                    app_language,
                )
            file_locations_md = ""
            if CI_MODE:
                file_locations_md = Markdown(
                    MD_LIST_MARKER
                    + MD_LIST_MARKER.join(
                        [
                            f"[{fl}]({to_local_path(full_path_prefix, fl)})"
                            for fl in files_loc_list
                        ]
                    )
                )
            # elif "win32" in sys.platform and not CI_MODE:
            #     file_locations_md = "\n\n".join(
            #         [f"{to_local_path(full_path_prefix, fl)}" for fl in files_loc_list]
            #     )
            else:
                file_locations_md = file_locations_tree(
                    afinding.get("internal_id"),
                    afinding.get("category"),
                    files_loc_list,
                    files_method_list,
                    http_routes,
                    tracked_list,
                    full_path_prefix,
                )
            if CI_MODE:
                table.add_row(
                    f"""[link={deep_link}]{afinding.get("id")}[/link]""",
                    cvss_31_severity_rating,
                    category,
                    file_locations_md,
                    Markdown(best_fix),
                )
            else:
                table.add_row(
                    f"""[link={deep_link}]{afinding.get("id")}[/link]""",
                    f"""{'[bold red]' if cvss_31_severity_rating == 'critical' else '[yellow]'}{cvss_31_severity_rating}""",
                    file_locations_md,
                    Markdown(best_fix),
                )
            annotated_findings.append(
                {
                    "id": afinding.get("id"),
                    "deep_link": deep_link,
                    "category": category,
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
                    "parameter_tags": "\n".join(list(ptags_set)),
                    "method_tags": "\n".join(list(mtags_set)),
                    "check_methods": "\n".join(check_methods),
                    "code_snippet": code_snippet.replace("\n", "\\n"),
                    "best_fix": best_fix.replace("\n", "\\n"),
                    "suppressable_finding": suppressable_finding,
                }
            )
        ###########
        ###########
        if afinding.get("type") == "oss_vuln":
            fix = details.get("fix", "")
            package_cves[package_url].append(
                {
                    "id": afinding.get("id"),
                    "cve": cve,
                    "oss_internal_id": oss_internal_id,
                    "fix": fix,
                    "cvss_31_severity_rating": cvss_31_severity_rating,
                    "reachability": reachability,
                }
            )
            if reachability == "reachable":
                reachable_oss_count += 1
            else:
                unreachable_oss_count += 1
        ###########
    # Executive summary section
    if scan:
        print_scan_stats(scan, counts)
    # Find the best oss fixes
    find_best_oss_fix(
        org_id,
        app,
        scan,
        package_cves,
        source_dir,
        reachable_oss_count,
        unreachable_oss_count,
    )
    if data_found:
        # Print Bestfix table
        console.print("\n\n")
        console.print(table)
        cohort_analysis(
            app["id"], scan.get("id"), source_cohorts, sink_cohorts, source_sink_cohorts
        )
    else:
        console.print("\n")
        console.print(
            Panel(
                f"""No critical or high findings found to suggest best fixes for {app["id"]}.""",
                title=f"""Best Fix Suggestions for {app["id"]}""",
                expand=False,
            )
        )
    # Annotate the pull request
    if os.getenv("GITHUB_TOKEN"):
        GitHubLib.annotate(annotated_findings, scan, False)
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


def get_all_findings_with_scan(client, org_id, app_name, version, ratings):
    """Method to retrieve all findings"""
    findings_list = []
    version_suffix = f"&version={version}" if version else ""
    findings_url = f"https://{config.SHIFTLEFT_API_HOST}/api/v4/orgs/{org_id}/apps/{app_name}/findings?per_page=249&type=oss_vuln&type=vuln&include_dataflows=true{version_suffix}"
    for rating in ratings:
        findings_url = f"{findings_url}&finding_tags=cvss_31_severity_rating={rating}"
    page_available = True
    scan = {}
    counts = []
    while page_available:
        try:
            r = client.get(findings_url, headers=headers, timeout=config.timeout)
        except httpx.ReadTimeout:
            console.print(
                f"Unable to retrieve findings for {app_name} due to timeout after {config.timeout} seconds"
            )
            continue
        except Exception:
            console.print(f"Unable to retrieve findings for {app_name}")
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
    return scan, findings_list, counts


def export_report(
    org_id,
    app_list,
    report_file,
    rformat,
    source_dir,
    version=None,
    ratings=["critical", "high"],
    troubleshoot=False,
):
    if not app_list:
        app_list = get_all_apps(org_id)
        if not app_list:
            return
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
        with httpx.Client(http2="win32" not in sys.platform, limits=limits) as client:
            for app in app_list:
                app_id = app.get("id")
                app_name = app.get("name")
                if app_name in ("Benchmark"):
                    continue
                progress.update(task, description=f"Processing [bold]{app_name}[/bold]")
                scan, findings, counts = get_all_findings_with_scan(
                    client, org_id, app_id, version, ratings
                )
                annotated_findings = find_best_fix(
                    org_id, app, scan, findings, counts, source_dir
                )
                if troubleshoot:
                    if scan:
                        troubleshoot_app(
                            client,
                            org_id,
                            app_name,
                            scan,
                            findings,
                            source_dir,
                            annotated_findings,
                        )
                    else:
                        console.print(
                            f"\nNo scan information found for {app_name}. Please review your build pipeline logs for troubleshooting."
                        )
                if rformat == "csv":
                    export_csv([app], annotated_findings, report_file)
                progress.advance(task)


def build_args():
    """
    Constructs command line arguments for the bestfix script
    """
    parser = argparse.ArgumentParser(description="Qwiet.AI preZero bestfix")
    parser.add_argument(
        "-a",
        "--app",
        dest="app_name",
        help="App name",
        default=config.SHIFTLEFT_APP,
    )
    parser.add_argument(
        "-v",
        "--version",
        dest="version",
        help="Scan version",
    )
    parser.add_argument(
        "-s", "--source_dir", dest="source_dir", help="Source directory"
    )
    parser.add_argument(
        "-o",
        "--report_file",
        dest="report_file",
        help="Report filename",
        default="ngsast-bestfix-report.html",
    )
    parser.add_argument(
        "-f",
        "--format",
        dest="rformat",
        help="Report format",
        default="html",
        choices=["html", "svg"],
    )
    parser.add_argument(
        "--troubleshoot",
        action="store_true",
        dest="troubleshoot",
        help="Troubleshoot apps with low findings count",
        default=True,
    )
    parser.add_argument(
        "--all-ratings",
        action="store_true",
        dest="all_ratings",
        help="Report for all CVSS 3.1 ratings. Default is critical and high only.",
        default=False,
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
    report_file = args.report_file
    # Use the app name in the default file name
    if args.app_name:
        app_list.append({"id": args.app_name, "name": args.app_name})
        if report_file == "ngsast-bestfix-report.html":
            report_file = f"ngsast-bestfix-{args.app_name}.html"
    report_dir = os.path.dirname(report_file)
    if report_dir:
        os.makedirs(report_dir, exist_ok=True)
    source_dir = args.source_dir
    if not source_dir:
        source_dir = os.getcwd()
        for e in ["GITHUB_WORKSPACE", "WORKSPACE"]:
            if os.getenv(e):
                source_dir = os.getenv(e)
                break
    export_report(
        org_id,
        app_list,
        report_file,
        args.rformat,
        source_dir,
        args.version,
        ["critical", "high", "medium", "low"]
        if args.all_ratings
        else ["critical", "high"],
        args.troubleshoot,
    )
    end_time = time.monotonic_ns()
    total_time_sec = round((end_time - start_time) / 1000000000, 2)
    if args.rformat == "html":
        console.save_html(
            report_file,
            theme=MONOKAI if os.getenv("USE_DARK_THEME") else DEFAULT_TERMINAL_THEME,
        )
        console.print(f"HTML report saved to {report_file}")
        try:
            import pdfkit

            pdf_file = report_file.replace(".html", ".pdf")
            pdfkit.from_file(report_file, pdf_file, options=pdf_options)
            console.print(f"PDF report saved to {pdf_file}")
        except Exception:
            console.print(
                "Please install wkhtmltopdf to enable PDF exports https://wkhtmltopdf.org/downloads.html"
            )
    elif args.rformat == "svg":
        report_file = report_file.replace(".html", ".svg")
        console.save_svg(
            report_file,
            theme=MONOKAI if os.getenv("USE_DARK_THEME") else DEFAULT_TERMINAL_THEME,
        )
        console.print(f"HTML report saved to {report_file}")
