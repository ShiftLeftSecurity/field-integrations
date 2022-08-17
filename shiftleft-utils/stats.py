# Usage: python3 stats.py

import argparse
import csv
import json
import os
import sys
import time

import requests
from rich.progress import Progress

import config
from common import extract_org_id, get_all_apps, get_findings_url

headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {config.SHIFTLEFT_ACCESS_TOKEN}",
}


def collect_stats(org_id, report_file):
    """Method to collect stats for all apps to a csv"""
    apps_list = get_all_apps(org_id)
    if not apps_list:
        print("No apps were found in this organization")
        return
    print(f"Found {len(apps_list)} apps in this organization")
    with open(report_file, "w", newline="") as csvfile:
        reportwriter = csv.writer(
            csvfile, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
        )
        reportwriter.writerow(
            [
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
            ]
        )
        with Progress(
            transient=True,
            redirect_stderr=False,
            redirect_stdout=False,
            refresh_per_second=1,
        ) as progress:
            task = progress.add_task(
                "[green] Collect stats", total=len(apps_list), start=True
            )
            for app in apps_list:
                app_id = app.get("id")
                app_name = app.get("name")
                progress.update(task, description=f"Processing [bold]{app_name}[/bold]")
                findings_url = get_findings_url(org_id, app_id, None)
                r = requests.get(findings_url, headers=headers)
                if r.ok:
                    raw_response = r.json()
                    if raw_response and raw_response.get("response"):
                        response = raw_response.get("response")
                        total_count = response.get("total_count")
                        scan = response.get("scan")
                        # Scan will be None if there are any issues/errors
                        if not scan:
                            continue
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
                            if c["finding_type"] in ["vuln", "secret"]
                            and c["key"] in ["severity", "language"]
                        ]
                        critical_count = 0
                        high_count = 0
                        medium_count =0
                        low_count = 0
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
                            if vc["finding_type"] == "vuln" and vc["key"] == "severity":
                                if vc["value"] == "critical":
                                    critical_count = vc["count"]
                                elif vc["value"] == "high":
                                    high_count = vc["count"]
                                elif vc["value"] == "medium":
                                    medium_count = vc["count"]    
                                elif vc["value"] == "low":
                                    low_count = vc["count"]
                            if (
                                vc["finding_type"] == "secret"
                                and vc["key"] == "language"
                            ):
                                secrets_count = vc["count"]
                        reportwriter.writerow(
                            [
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
                            ]
                        )
                else:
                    progress.console.print(
                        f"""Unable to retrieve findings for {app_name}"""
                    )
                    progress.console.print(r.status_code, r.json())
                progress.advance(task)
    print(f"Stats written to {report_file}")


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
    return parser.parse_args()


if __name__ == "__main__":
    if not config.SHIFTLEFT_ACCESS_TOKEN:
        print(
            "Set the environment variable SHIFTLEFT_ACCESS_TOKEN before running this script"
        )
        sys.exit(1)

    org_id = extract_org_id(config.SHIFTLEFT_ACCESS_TOKEN)
    if not org_id:
        print(
            "Ensure the environment varibale SHIFTLEFT_ACCESS_TOKEN is copied exactly as-is from the website"
        )
        sys.exit(1)
    print(config.ngsast_logo)
    args = build_args()
    start_time = time.monotonic_ns()
    report_file = args.report_file
    collect_stats(org_id, report_file)
    end_time = time.monotonic_ns()
    total_time_sec = round((end_time - start_time) / 1000000000, 2)
