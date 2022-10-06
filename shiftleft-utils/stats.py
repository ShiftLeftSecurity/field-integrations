# Usage: python3 stats.py

import argparse
import csv
import functools
import json
import math
import multiprocessing
import os
import sys
import time
from datetime import datetime

import httpx
from rich.console import Console
from rich.live import Live
from rich.progress import Progress
from rich.table import Table

import config
from common import (
    extract_org_id,
    get_all_apps,
    get_findings_counts_url,
    get_findings_url,
    headers,
)

console = Console(color_system="auto")


def process_app(client, org_id, report_file, app, detailed):
    start = time.time()
    app_id = app.get("id")
    app_name = app.get("name")
    # Stats only considers the first page for performance so the detailed report is based only on the latest 250 findings
    # The various counts, however, are based on the full list of findings so are correct
    findings_url = (
        get_findings_url(org_id, app_id, None)
        if detailed
        else get_findings_counts_url(org_id, app_id, None)
    )
    r = None
    try:
        r = client.get(findings_url, headers=headers, timeout=config.timeout)
    except httpx.RequestError as exc:
        print(f"""Unable to retrieve findings for {app_name}""")
        return None, None
    if r and r.status_code == 200:
        raw_response = r.json()
        if raw_response and raw_response.get("response"):
            response = raw_response.get("response")
            total_count = response.get("total_count")
            scan = response.get("scan")
            # Scan will be None if there are any issues/errors
            if not scan:
                return
            tags = app.get("tags")
            app_group = ""
            if tags:
                for tag in tags:
                    if tag.get("key") == "group":
                        app_group = tag.get("value")
                        break
            # Other unused properties such as findings or counts
            spid = scan.get("internal_id")
            projectSpId = f'sl/{org_id}/{scan.get("app")}'
            counts = response.get("counts", [])
            findings = response.get("findings", [])
            vuln_counts = [
                c
                for c in counts
                if c["finding_type"] in ["vuln", "secret", "oss_vuln", "container"]
                and c["key"]
                in [
                    "severity",
                    "language",
                    "cvss_31_severity_rating",
                    "reachable_oss_vulns",
                    "reachability",
                ]
            ]
            critical_count = 0
            high_count = 0
            medium_count = 0
            low_count = 0
            oss_critical_count = 0
            oss_high_count = 0
            oss_medium_count = 0
            oss_low_count = 0
            container_critical_count = 0
            container_high_count = 0
            container_medium_count = 0
            container_low_count = 0
            oss_reachable_count = 0
            oss_unreachable_count = 0
            reachable_oss_vulns = 0
            secrets_count = 0
            sources_list = set()
            sinks_list = set()
            files_loc_list = set()
            methods_list = set()
            routes_list = set()
            secrets_list = set()
            entropy_low = 0
            entropy_high = 0
            # Find the source and sink
            for afinding in findings:
                details = afinding.get("details", {})
                if details.get("source_method") and "{" not in details.get(
                    "source_method"
                ):
                    sources_list.add(details.get("source_method").replace("\n", " "))
                if details.get("sink_method") and "{" not in details.get("sink_method"):
                    sinks_list.add(details.get("sink_method").replace("\n", " "))
                if details.get("file_locations"):
                    files_loc_list.update(details.get("file_locations"))
                if details.get("secret"):
                    secrets_list.update(details.get("secret"))
                if details.get("entropy"):
                    try:
                        entropy = float(details.get("entropy"))
                        if entropy_low == 0:
                            entropy_low = entropy
                        if entropy_high == 0:
                            entropy_high = entropy
                        if entropy_low > entropy:
                            entropy_low = entropy
                        if entropy_high < entropy:
                            entropy_high = entropy
                    except Exception:
                        pass
                dfobj = {}
                if details.get("dataflow"):
                    dfobj = details.get("dataflow")
                dataflows = dfobj.get("list", [])
                for i, df in enumerate(dataflows):
                    method_tags = df.get("method_tags", [])
                    mtags = [
                        mt.get("value")
                        for mt in method_tags
                        if mt.get("key", "") in ("EXPOSED_METHOD_ROUTE", 30)
                        and mt.get("value")
                    ]
                    route_value = mtags[0] if mtags else None
                    if route_value:
                        routes_list.add(route_value)
                    location = df.get("location", {})
                    if location.get("file_name") == "N/A" or not location.get(
                        "line_number"
                    ):
                        continue
                    method_name = location.get("method_name")
                    if (
                        method_name
                        and method_name not in sinks_list
                        and method_name not in sources_list
                        and "{" not in method_name
                    ):
                        methods_list.add(method_name)
            # Find the counts
            for vc in vuln_counts:
                if (
                    vc["finding_type"] == "vuln"
                    and vc["key"] == "cvss_31_severity_rating"
                ):
                    if vc["value"] == "critical":
                        critical_count = vc["count"]
                    elif vc["value"] == "high":
                        high_count = vc["count"]
                    elif vc["value"] == "medium":
                        medium_count = vc["count"]
                    elif vc["value"] == "low":
                        low_count = vc["count"]
                if vc["finding_type"] == "vuln" and vc["key"] == "reachable_oss_vulns":
                    reachable_oss_vulns = vc["count"]
                if (
                    vc["finding_type"] == "oss_vuln"
                    and vc["key"] == "cvss_31_severity_rating"
                ):
                    if vc["value"] == "critical":
                        oss_critical_count = vc["count"]
                    elif vc["value"] == "high":
                        oss_high_count = vc["count"]
                    elif vc["value"] == "medium":
                        oss_medium_count = vc["count"]
                    elif vc["value"] == "low":
                        oss_low_count = vc["count"]
                if vc["finding_type"] == "oss_vuln" and vc["key"] == "reachability":
                    if vc["value"] == "unreachable":
                        oss_unreachable_count = vc["count"]
                    if vc["value"] == "reachable":
                        oss_reachable_count = vc["count"]
                if (
                    vc["finding_type"] == "container"
                    and vc["key"] == "cvss_31_severity_rating"
                ):
                    if vc["value"] == "critical":
                        container_critical_count = vc["count"]
                    elif vc["value"] == "high":
                        container_high_count = vc["count"]
                    elif vc["value"] == "medium":
                        container_medium_count = vc["count"]
                    elif vc["value"] == "low":
                        container_low_count = vc["count"]
                if vc["finding_type"] == "secret" and vc["key"] == "language":
                    secrets_count = vc["count"]
            # Convert date time to BigQuery friendly format
            completed_at = ""
            try:
                ctime = scan.get("completed_at", "")
                completed_at_dt = datetime.strptime(
                    ctime,
                    "%Y-%m-%dT%H:%M:%S.%fZ %Z"
                    if "UTC" in ctime
                    else "%Y-%m-%dT%H:%M:%S.%fZ",
                )
                completed_at = completed_at_dt.strftime("%Y-%m-%d %H:%M:%S.%f")
            except Exception as e:
                completed_at = (
                    scan.get("completed_at", "")
                    .replace(" UTC", "")
                    .replace("Z", "")
                    .replace("T", " ")
                )
            return [
                scan.get("app"),
                app_group,
                scan.get("version"),
                completed_at,
                scan.get("language"),
                scan.get("number_of_expressions"),
                critical_count,
                high_count,
                medium_count,
                low_count,
                secrets_count,
                "\\n".join(sources_list),
                "\\n".join(sinks_list),
                "\\n".join(files_loc_list),
                oss_critical_count,
                oss_high_count,
                oss_medium_count,
                oss_low_count,
                oss_reachable_count,
                oss_unreachable_count,
                container_critical_count,
                container_high_count,
                container_medium_count,
                container_low_count,
                "\\n".join(methods_list),
                "\\n".join(routes_list),
                "\\n".join(secrets_list),
                entropy_low,
                entropy_high,
            ], math.ceil(time.time() - start)
    else:
        print(f"""Unable to retrieve findings for {app_name}""")
        return None, None


def collect_stats(org_id, report_file, detailed):
    """Method to collect stats for all apps to a csv"""
    apps_list = get_all_apps(org_id)
    attention_apps = 0
    if not apps_list:
        console.print("No apps were found in this organization")
        return
    if detailed:
        console.print(
            f"Found {len(apps_list)} apps in this organization. Estimated time: {math.ceil(len(apps_list)/3.2)} minutes!"
        )
    else:
        console.print(
            f"Found {len(apps_list)} apps in this organization. Estimated time: {math.ceil(len(apps_list)*1.5/60)} minutes!"
        )
    with open(report_file, "w", newline="") as csvfile:
        reportwriter = csv.writer(
            csvfile, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
        )
        csv_cols = [
            "App",
            "App Group",
            "Version",
            "Last Scan",
            "Language",
            "Expressions Count",
            "Critical Count",
            "High Count",
            "Medium Count",
            "Low Count",
            "Secrets Count",
            "Source Methods",
            "Sink Methods",
            "File Locations",
            "OSS Critical Count",
            "OSS High Count",
            "OSS Medium Count",
            "OSS Low Count",
            "OSS Reachable Count",
            "OSS Unreachable Count",
            "Container Critical Count",
            "Container High Count",
            "Container Medium Count",
            "Container Low Count",
            "Methods",
            "Routes",
            "Secrets",
            "Entropy Low",
            "Entropy High",
        ]
        reportwriter.writerow(csv_cols)
        table = Table(title="App Stats", highlight=True)
        table.add_column("#")
        table.add_column("Script Time\n(Seconds)", justify="right")
        table.add_column("App")
        table.add_column("Critical", justify="right")
        table.add_column("High", justify="right")
        table.add_column("Secrets", justify="right")
        table.add_column("OSS Critical", justify="right")
        table.add_column("OSS High", justify="right")
        table.add_column("OSS Reachable", justify="right")
        with Live(
            table,
            refresh_per_second=2,
            vertical_overflow="visible",
            screen=False,
            console=console,
        ) as live:
            # with Progress(
            #     transient=True,
            #     redirect_stderr=False,
            #     redirect_stdout=False,
            #     refresh_per_second=1,
            # ) as progress:
            limits = httpx.Limits(
                max_keepalive_connections=20, max_connections=100, keepalive_expiry=120
            )
            with httpx.Client(http2="win" not in sys.platform, limits=limits) as client:
                # task = progress.add_task(
                #     "[green] Collect stats", total=len(apps_list), start=True
                # )
                i = 1
                for app in apps_list:
                    # progress.update(
                    #     task,
                    #     description=f"""Processing [bold]{app.get("name")}[/bold]""",
                    # )
                    row, time_taken = process_app(
                        client, org_id, report_file, app, detailed
                    )
                    if row:
                        reportwriter.writerow(row)
                        needs_attention = row[6] > 0 and row[18] > 0
                        if needs_attention:
                            attention_apps += 1
                        table.add_row(
                            f"{i}",
                            f"""{time_taken if time_taken else ""}""",
                            f"""{"[red]" if needs_attention else ""}{row[0]}""",
                            f"""{"[red]" if needs_attention else ""}{row[6]}""",
                            f"{row[7]}",
                            f"{row[10]}",
                            f"{row[14]}",
                            f"{row[15]}",
                            f"""{"[red]" if needs_attention else ""}{row[18]}""",
                        )
                        i = i + 1
                    # progress.advance(task)
    console.print(f"Stats written to {report_file}")
    console.print(
        f"[red]{attention_apps}[/red] apps needs attention due to both Critical SAST and Reachable OSS findings"
    )


def build_args():
    """
    Constructs command line arguments for the export script
    """
    parser = argparse.ArgumentParser(description="ShiftLeft NG SAST stats script")
    parser.add_argument(
        "-o",
        "--report_file",
        dest="report_file",
        help="Report filename",
        default="stats.csv",
    )
    parser.add_argument(
        "--detailed",
        action=argparse.BooleanOptionalAction,
        dest="detailed",
        help="Detailed stats including sources, sinks and file location",
        default=False,
    )
    return parser.parse_args()


def main():
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
    args = build_args()
    report_file = args.report_file
    collect_stats(org_id, report_file, args.detailed)


if __name__ == "__main__":
    main()
