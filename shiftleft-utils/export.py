# Usage: python3 export.py -a app name

import argparse
import json
import os
import sys
import time

import requests
from json2xml import json2xml

import config


def get_findings_url(app_name):
    return f"https://www.shiftleft.io/api/v4/orgs/{config.SHIFTLEFT_ORG_ID}/apps/{app_name}/findings?per_page=249"


def get_all_findings(app_name, report_file, format):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {config.SHIFTLEFT_ACCESS_TOKEN}",
    }
    findings_list = []
    findings_url = get_findings_url(app_name)
    page_available = True
    while page_available:
        # print (findings_url)
        r = requests.get(findings_url, headers=headers)
        if r.ok:
            raw_response = r.json()
            if raw_response and raw_response.get("response"):
                response = raw_response.get("response")
                total_count = response.get("total_count")
                scan = response.get("scan")
                scan_id = scan.get("id")
                spid = scan.get("internal_id")
                projectSpId = f'sl/{config.SHIFTLEFT_ORG_ID}/{scan.get("app")}'
                findings = response.get("findings")
                counts = response.get("counts")
                link = f"https://www.shiftleft.io/findingsSummary/{app_name}?apps={app_name}&isApp=1"
                # print(f"Total issues found: {total_count}")
                findings_list += findings
                if raw_response.get("next_page"):
                    findings_url = raw_response.get("next_page")
                else:
                    page_available = False
        else:
            print(f"Unable to retrieve findings for {app_name}")
            print(r.status_code, r.json())
    if not len(findings_list) == total_count:
        print(f"Couldn't retrieve all {total_count} findings")
    return findings_list


def export_report(app_name, report_file, format):
    findings = get_all_findings(app_name, report_file, format)
    with open(report_file, mode="w") as rp:
        if format == "xml" or report_file.endswith(".xml"):
            xml_data = json2xml.Json2xml(findings).to_xml()
            rp.write(xml_data)
            print(f"Findings report successfully exported to {report_file}")
        elif format == "sl":
            for af in findings:
                title = af.get("title")
                filename = title.split(" in ")[-1].replace("`", "").split(".")[0]
                if filename.startswith("BenchmarkTest"):
                    filename = filename.replace("BenchmarkTest", "")
                else:
                    print(f"Unable to extract filename from title {title}")
                tags = af.get("tags")
                cwe_id = ""
                category = af.get("description")
                for tag in tags:
                    if tag["key"] == "category":
                        category = tag["value"]
                    if tag["key"] == "cwe_category":
                        cwe_id = tag["value"]
                if not category and cwe_id == "384":
                    category = "Broken Authentication"
                if config.sl_owasp_category.get(category):
                    category = config.sl_owasp_category.get(category)
                    rp.write(f"{filename},{category}\n")
                else:
                    print(filename, tags)
            print(f"Findings report successfully exported to {report_file}")
        else:
            json.dump(findings, rp, indent=config.json_indent)
            print(f"Findings report successfully exported to {report_file}")


def build_args():
    """
    Constructs command line arguments for the export script
    """
    parser = argparse.ArgumentParser(description="ShiftLeft NG SAST export script")
    parser.add_argument(
        "-a",
        "--app",
        dest="app_name",
        required=True,
        help="App name",
        default=config.SHIFTLEFT_APP,
    )
    parser.add_argument(
        "-o",
        "--report_file",
        dest="report_file",
        help="Report filename",
        default="ngsast-report.json",
    )
    parser.add_argument(
        "-f",
        "--format",
        dest="format",
        help="Report format",
        default="json",
        choices=["json", "xml", "sl"],
    )
    return parser.parse_args()


if __name__ == "__main__":
    if not config.SHIFTLEFT_ORG_ID or not config.SHIFTLEFT_ACCESS_TOKEN:
        print(
            "Set the environment variables SHIFTLEFT_ORG_ID and SHIFTLEFT_ACCESS_TOKEN before running this script"
        )
        sys.exit(1)

    print(config.ngsast_logo)
    start_time = time.monotonic_ns()
    args = build_args()
    app_name = args.app_name
    report_file = args.report_file
    format = args.format
    # Fix file extensions for xml format
    if format == "xml":
        report_file = report_file.replace(".json", ".xml")
    elif format == "sl":
        print(
            "WARNING: This is work-in-progress and is not ready for official benchmarking purposes yet!!!"
        )
        print(
            "Please contact ShiftLeft if you are interested in an official benchmark script"
        )
        report_file = "Benchmark_1.2-ShiftLeft.sl"
    export_report(app_name, report_file, format)
    end_time = time.monotonic_ns()
    total_time_sec = round((end_time - start_time) / 1000000000, 2)
