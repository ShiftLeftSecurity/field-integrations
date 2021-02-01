# Usage: python3 export.py -a app name

import argparse
import json
import os
import sys
import time

import requests
from json2xml import json2xml

import config

# Authentication headers for all API
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {config.SHIFTLEFT_ACCESS_TOKEN}",
}


def get_findings_url(app_name):
    return f"https://www.shiftleft.io/api/v4/orgs/{config.SHIFTLEFT_ORG_ID}/apps/{app_name}/findings?per_page=249&type=vuln&include_dataflows=true"


def get_all_findings(app_name, report_file, format):
    """Method to retrieve all findings"""
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
                findings_list += findings
                print(
                    f"Findings retrieved so far: {len(findings_list)} / {total_count}"
                )
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


def get_dataflow(app_name, finding_id):
    finding_url = f"https://www.shiftleft.io/api/v4/orgs/{config.SHIFTLEFT_ORG_ID}/apps/{app_name}/findings/{finding_id}?include_dataflows=true"
    r = requests.get(finding_url, headers=headers)
    if r.ok:
        raw_response = r.json()
        if raw_response and raw_response.get("response"):
            response = raw_response.get("response")
            details = response.get("details")
            dataflow = details.get("dataflow", {}).get("list")
            return dataflow
    else:
        print(f"Unable to retrieve dataflows for {finding_id}")
        print(r.status_code, r.json())
        return None


def export_report(app_name, report_file, format):
    findings = get_all_findings(app_name, report_file, format)
    file_category_set = set()
    with open(report_file, mode="w") as rp:
        if format == "xml" or report_file.endswith(".xml"):
            xml_data = json2xml.Json2xml(findings).to_xml()
            rp.write(xml_data)
            print(f"Findings report successfully exported to {report_file}")
        elif format == "sl":
            for af in findings:
                details = af.get("details")
                title = af.get("title")
                # filename could be found either in file_locations or fileName
                filename = ""
                if details and details.get("file_locations"):
                    file_locations = details.get("file_locations")
                    if len(file_locations):
                        filename = file_locations[0].split(":")[0].split("/")[-1]
                        filename = filename.replace(".java", "")
                # If there is no file_locations try to extract the name from the title
                if not filename and "BenchmarkTest" in title:
                    filename = title.split(" in ")[-1].replace("`", "").split(".")[0]
                if filename.startswith("BenchmarkTest"):
                    filename = filename.replace("BenchmarkTest", "")
                else:
                    # Try to get the filename from source_method in details
                    source_method = details.get("source_method")
                    if source_method and "BenchmarkTest" in source_method:
                        filename = source_method.split(":")[0].split(".")[4]
                        filename = filename.replace("BenchmarkTest", "")
                    else:
                        print(f'Get dataflow for {af.get("id")}')
                        # dataflows = get_dataflow(app_name, af.get("id"))
                        dataflows = details.get("dataflow", {}).get("list")
                        if dataflows:
                            for df in dataflows:
                                location = df.get("location")
                                if location.get(
                                    "class_name"
                                ) and "BenchmarkTest" in location.get("class_name"):
                                    filename = location.get("class_name").split(".")[-1]
                                    filename = filename.replace("BenchmarkTest", "")
                                    break
                if not filename:
                    print(
                        f"Unable to extract filename from file_locations or title {title}. Skipping ..."
                    )
                    continue
                tags = af.get("tags")
                cwe_id = ""
                category = af.get("title")
                for tag in tags:
                    if tag["key"] == "category":
                        category = tag["value"]
                    if tag["key"] == "cwe_category":
                        cwe_id = tag["value"]
                if not category and cwe_id == "384":
                    category = "Broken Authentication"
                if config.sl_owasp_category.get(category):
                    category = config.sl_owasp_category.get(category)
                file_category = f"{filename},{category}"
                if " " not in category and file_category not in file_category_set:
                    rp.write(file_category + "\n")
                    file_category_set.add(file_category)
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
            "WARNING: This functionality is a work-in-progress and is not ready for official benchmarking purposes yet!!!"
        )
        print(
            "Please contact ShiftLeft if you are interested in an official benchmark script"
        )
        if not report_file:
            report_file = "Benchmark_1.2-ShiftLeft.sl"
    export_report(app_name, report_file, format)
    end_time = time.monotonic_ns()
    total_time_sec = round((end_time - start_time) / 1000000000, 2)
