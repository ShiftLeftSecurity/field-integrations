# Usage: python3 stats.py

import argparse
import csv
import functools
import json
import multiprocessing
import os
import sys
import time

import httpx
import trio
import trio_parallel
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
)

console = Console(color_system="auto")

headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {config.SHIFTLEFT_ACCESS_TOKEN}",
    "Accept-Encoding": "gzip",
}


def process_app(client, org_id, report_file, app, detailed):
    app_id = app.get("id")
    app_name = app.get("name")
    findings_url = (
        get_findings_url(org_id, app_id, None)
        if detailed
        else get_findings_counts_url(org_id, app_id, None)
    )
    r = client.get(findings_url, headers=headers, timeout=config.timeout)
    if r.status_code == 200:
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
            # Find the source and sink
            for afinding in findings:
                details = afinding.get("details", {})
                if details.get("source_method"):
                    sources_list.add(details.get("source_method"))
                if details.get("sink_method"):
                    sinks_list.add(details.get("sink_method"))
                if details.get("file_locations"):
                    files_loc_list.update(details.get("file_locations"))
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
            return [
                scan.get("app"),
                app_group,
                scan.get("version"),
                scan.get("completed_at"),
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
            ]
    else:
        console.print(f"""Unable to retrieve findings for {app_name}""")
        return None


def collect_stats(org_id, report_file, detailed):
    """Method to collect stats for all apps to a csv"""
    apps_list = get_all_apps(org_id)
    attention_apps = 0
    if not apps_list:
        console.print("No apps were found in this organization")
        return
    console.print(
        f"Found {len(apps_list)} apps in this organization. Please wait for CSV report."
    )
    console.print(
        "Highlighting apps with critical OWASP and Reachable OSS findings ..."
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
        ]
        reportwriter.writerow(csv_cols)
        table = Table()
        table.add_column("App")
        table.add_column("Critical")
        table.add_column("High")
        table.add_column("Secrets")
        table.add_column("OSS Critical")
        table.add_column("OSS High")
        table.add_column("OSS Reachable")
        with Live(table, refresh_per_second=4):
            # with Progress(
            #     transient=True,
            #     redirect_stderr=False,
            #     redirect_stdout=False,
            #     refresh_per_second=1,
            # ) as progress:
            limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
            with httpx.Client(http2=True, limits=limits) as client:
                # task = progress.add_task(
                #     "[green] Collect stats", total=len(apps_list), start=True
                # )
                for app in apps_list:
                    # progress.update(
                    #     task,
                    #     description=f"""Processing [bold]{app.get("name")}[/bold]""",
                    # )
                    row = process_app(client, org_id, report_file, app, detailed)
                    if row:
                        reportwriter.writerow(row)
                        needs_attention = row[6] > 0 and row[18] > 0
                        if needs_attention:
                            attention_apps += 1
                        table.add_row(
                            f"""{"[red]" if needs_attention else ""}{row[0]}""",
                            f"""{"[red]" if needs_attention else ""}{row[6]}""",
                            f"{row[7]}",
                            f"{row[10]}",
                            f"{row[14]}",
                            f"{row[15]}",
                            f"""{"[red]" if needs_attention else ""}{row[18]}""",
                        )
                    # progress.advance(task)
    console.print(f"Stats written to {report_file}")
    console.print(f"[red]{attention_apps}[/red] apps needs your attention")


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


async def parallel_map(fn):
    async def worker(inp):
        await trio_parallel.run_sync(fn, *inp, cancellable=True)

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
    t0 = trio.current_time()
    report_file = args.report_file
    async with trio.open_nursery() as nursery:
        nursery.start_soon(
            worker,
            (org_id, report_file, args.detailed),
        )
        t1 = trio.current_time()
    console.print("Time taken:", round(trio.current_time() - t0, 0), "seconds")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    trio.run(parallel_map, collect_stats)
