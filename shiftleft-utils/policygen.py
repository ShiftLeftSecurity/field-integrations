# Usage: python3 policygen.py -a app name

import argparse
import json
import os
import sys
from collections import defaultdict

from rich.markdown import Markdown
from rich.panel import Panel

import config
from common import (
    LOG,
    console,
    extract_org_id,
    get_all_apps,
    get_all_findings,
    get_dataflow,
    get_findings_url,
)

POLICY_TEMPLATE = """
IMPORT io.shiftleft/default
IMPORT io.shiftleft/defaultdict

###############################################################################
# Policy file for ShiftLeft NG SAST
# All findings containing the tag CHECK would get suppressed.
###############################################################################

"""

CHECK_METHOD_TEMPLATE = """TAG "CHECK" METHOD -f "%(method_name)s"
"""


def start_analysis(org_id, app_name, version):
    """Method to analyze all the findings to identify sources, sinks, methods and file locations"""
    findings = get_all_findings(org_id, app_name, version)
    sources_list = set()
    sources_dict = defaultdict(set)
    methods_list = set()
    sinks_dict = defaultdict(set)
    files_loc_list = set()
    sinks_list = set()
    # Find the source and sink
    for afinding in findings:
        category = afinding.get("category")
        details = afinding.get("details", {})
        if details.get("source_method"):
            sources_dict[category].add(details.get("source_method"))
            sources_list.add(details.get("source_method"))
        if details.get("sink_method"):
            sinks_dict[category].add(details.get("sink_method"))
            sinks_list.add(details.get("sink_method"))
        if details.get("file_locations"):
            files_loc_list.update(details.get("file_locations"))
        dfobj = {}
        if details.get("dataflow"):
            dfobj = details.get("dataflow")
        dataflows = dfobj.get("list", [])
        for df in dataflows:
            location = df.get("location", {})
            if location.get("file_name") == "N/A" or not location.get("line_number"):
                continue
            method_name = location.get("method_name")
            if method_name not in sinks_list and method_name not in sources_list:
                methods_list.add(method_name)
    return sources_dict, sinks_dict, methods_list, files_loc_list


def create_policy(
    org_id,
    app_name,
    sources_dict,
    sinks_dict,
    methods_list,
    files_loc_list,
    policy_file,
):
    """Method to create a sample policy file for the app"""
    if os.path.exists(policy_file):
        LOG.info(f"WARNING: {policy_file} would be overwritten")
    with open(policy_file, mode="w") as fp:
        fp.write(POLICY_TEMPLATE)
        fp.write("#" * 79 + "\n")
        fp.write("# Sink methods #\n")
        fp.write("#" * 79 + "\n")
        for category, sinks_list in sinks_dict.items():
            fp.write("\n")
            fp.write("#" * 79 + "\n")
            fp.write(f"# Category {category} #\n")
            fp.write("#" * 79 + "\n")
            for sink in sinks_list:
                fp.write(CHECK_METHOD_TEMPLATE % dict(method_name=sink))
        fp.write("#" * 79 + "\n\n")
        fp.write("#" * 79 + "\n")
        fp.write("# All methods (Uncomment as needed) #\n")
        fp.write("#" * 79 + "\n")
        for method in methods_list:
            fp.write("# " + CHECK_METHOD_TEMPLATE % dict(method_name=method))
    console.print(
        Panel(
            f"Sample policy file [bold]{policy_file}[/bold] created successfully.\nTo use this policy perform the below steps as ShiftLeft administrator",
            title="ShiftLeft Policy Generator",
            expand=False,
        )
    )
    md = Markdown(
        f"""
```
sl policy validate {policy_file}
sl policy push apprules {policy_file}
sl policy assignment set --project {app_name} {org_id}/apprules:latest
```
"""
    )
    console.print(md)
    console.print(f"Then perform sl analyze as normal\n")
    console.print(
        Panel(
            f"Using this file as-is would suppress all findings for {app_name}!",
            title="NOTE",
            expand=False,
        )
    )


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
        required=True,
    )
    parser.add_argument(
        "-v",
        "--version",
        dest="version",
        help="Scan version",
    )
    parser.add_argument(
        "-p",
        "--policy",
        dest="policy_file",
        help="Policy filename to generate",
        default="ngsast.policy",
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
    sources_dict, sinks_dict, methods_list, files_loc_list = start_analysis(
        org_id, args.app_name, args.version
    )
    create_policy(
        org_id,
        args.app_name,
        sources_dict,
        sinks_dict,
        methods_list,
        files_loc_list,
        args.policy_file,
    )
