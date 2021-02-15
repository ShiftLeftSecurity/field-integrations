# Usage: python3 stats.py

import argparse
import csv
import json
import os
import sys
import time

import requests

import config


headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {config.SHIFTLEFT_ACCESS_TOKEN}",
}


def get_findings_url(app_name):
    """Return the findings url for the given app name"""
    return f"https://www.shiftleft.io/api/v4/orgs/{config.SHIFTLEFT_ORG_ID}/apps/{app_name}/findings?per_page=249&type=secret&type=vuln&type=extscan"


def get_all_apps():
    """Return all the apps for the given organization"""
    list_apps_url = (
        f"https://www.shiftleft.io/api/v4/orgs/{config.SHIFTLEFT_ORG_ID}/apps"
    )
    r = requests.get(list_apps_url, headers=headers)
    if r.ok:
        raw_response = r.json()
        if raw_response and raw_response.get("response"):
            apps_list = raw_response.get("response")
            return apps_list
    else:
        print(
            f"Unable to retrieve apps list for the organization {config.SHIFTLEFT_ORG_ID}"
        )
        print(r.status_code, r.json())
    return None


def collect_stats(report_file):
    """Method to collect stats for all apps to a csv"""
    apps_list = get_all_apps()
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
                "Language",
                "Expressions Count",
                "Critical Count",
                "Moderate Count",
                "Info Count",
                "Secrets Count",
                "Source Methods",
                "Sink Methods",
                "File Locations",
            ]
        )
        for app in apps_list:
            findings_url = get_findings_url(app.get("id"))
            print(f"""Collect stats for {app.get("id")}""")
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
                    projectSpId = f'sl/{config.SHIFTLEFT_ORG_ID}/{scan.get("app")}'
                    counts = response.get("counts", [])
                    findings = response.get("findings", [])

                    vuln_counts = [
                        c
                        for c in counts
                        if c["finding_type"] in ["vuln", "secret"]
                        and c["key"] in ["severity", "language"]
                    ]
                    critical_count = 0
                    moderate_count = 0
                    info_count = 0
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
                            elif vc["value"] == "moderate":
                                moderate_count = vc["count"]
                            elif vc["value"] == "info":
                                info_count = vc["count"]
                        if vc["finding_type"] == "secret" and vc["key"] == "language":
                            secrets_count = vc["count"]
                    reportwriter.writerow(
                        [
                            scan.get("app"),
                            app_group,
                            scan.get("version"),
                            scan.get("language"),
                            scan.get("number_of_expressions"),
                            critical_count,
                            moderate_count,
                            info_count,
                            secrets_count,
                            "\\n".join(sources_list),
                            "\\n".join(sinks_list),
                            "\\n".join(files_loc_list),
                        ]
                    )
            else:
                print(f"""Unable to retrieve findings for {app.get("name")}""")
                print(r.status_code, r.json())
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
    if not config.SHIFTLEFT_ORG_ID or not config.SHIFTLEFT_ACCESS_TOKEN:
        print(
            "Set the environment variables SHIFTLEFT_ORG_ID and SHIFTLEFT_ACCESS_TOKEN before running this script"
        )
        sys.exit(1)
    print(config.ngsast_logo)
    args = build_args()
    start_time = time.monotonic_ns()
    report_file = args.report_file
    collect_stats(report_file)
    end_time = time.monotonic_ns()
    total_time_sec = round((end_time - start_time) / 1000000000, 2)
