# Usage: python3 policygen.py -a app name

import argparse
import json
import os
import sys
from collections import defaultdict

from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress

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

POLICY_TEMPLATE = """IMPORT io.shiftleft/default
IMPORT io.shiftleft/defaultdict

###############################################################################
# Policy file for ShiftLeft NG SAST
# All findings containing the tag CHECK would get suppressed.
# Refer to https://docs.shiftleft.io/ngsast/policies/custom-policies
###############################################################################

"""

CHECK_METHOD_TEMPLATE = """TAG "CHECK" METHOD -f "%(method_name)s"
"""

REMEDIATION_TEMPLATE = """methods:
"""

REMEDIATION_METHOD_TEMPLATE = """  - method: %(method_name)s
    tags:
      - key: category
        value: %(category_name)s
"""


def start_analysis(org_id, app_name, version):
    """Method to analyze all the findings to identify sources, sinks, methods and file locations"""
    findings = get_all_findings(org_id, app_name, version)
    sources_list = set()
    sources_dict = defaultdict(set)
    vars_dict = defaultdict(set)
    methods_dict = defaultdict(set)
    methods_list = set()
    sinks_dict = defaultdict(set)
    files_loc_list = set()
    sinks_list = set()
    category_route_dict = defaultdict(dict)
    with Progress(
        transient=True,
        redirect_stderr=False,
        redirect_stdout=False,
        refresh_per_second=1,
    ) as progress:
        task = progress.add_task(
            "[green] Computing policy", total=len(findings), start=True
        )
        # Find the source and sink
        for afinding in findings:
            # Remediation is only supported for vuln findings
            if afinding.get("type") != "vuln":
                continue
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
            for i, df in enumerate(dataflows):
                if i == 0:
                    variableInfo = df.get("variable_info", {})
                    if variableInfo.get("variable"):
                        variableInfo = variableInfo.get("variable")
                    if variableInfo.get("Variable"):
                        variableInfo = variableInfo.get("Variable")
                    method_tags = df.get("method_tags", [])
                    mtags = [
                        mt.get("value")
                        for mt in method_tags
                        if mt.get("key", "") in ("EXPOSED_METHOD_ROUTE", 30)
                        and mt.get("value")
                    ]
                    route_value = mtags[0] if mtags else None
                    if variableInfo:
                        parameter = variableInfo.get("Parameter")
                        if not parameter:
                            parameter = variableInfo.get("parameter")
                        local = variableInfo.get("Local")
                        if not local:
                            local = variableInfo.get("local")
                        if parameter and parameter.get("symbol"):
                            symbol = parameter.get("symbol")
                            vars_dict[category].add(symbol)
                            if route_value:
                                category_route_dict[category][symbol] = route_value
                        if local and local.get("symbol"):
                            vars_dict[category].add(local.get("symbol"))
                location = df.get("location", {})
                if location.get("file_name") == "N/A" or not location.get(
                    "line_number"
                ):
                    continue
                method_name = location.get("method_name")
                if method_name not in sinks_list and method_name not in sources_list:
                    methods_list.add(method_name)
                    methods_dict[category].add(method_name)
            progress.advance(task)
    return (
        sources_dict,
        sinks_dict,
        methods_list,
        methods_dict,
        files_loc_list,
        vars_dict,
        category_route_dict,
    )


def create_remediation(
    org_id,
    app_name,
    sources_dict,
    sinks_dict,
    methods_dict,
    files_loc_list,
    remediation_file,
):
    """Method to create a sample remediation config file for the app"""
    if os.path.exists(remediation_file):
        LOG.info(f"WARNING: {remediation_file} would be overwritten")
    with open(remediation_file, mode="w") as fp:
        fp.write(REMEDIATION_TEMPLATE)
        for category, sources_list in sources_dict.items():
            for source in sorted(sources_list):
                fp.write(
                    REMEDIATION_METHOD_TEMPLATE
                    % dict(method_name=source, category_name=category)
                )
        for category, sinks_list in sinks_dict.items():
            for sink in sorted(sinks_list):
                fp.write(
                    REMEDIATION_METHOD_TEMPLATE
                    % dict(method_name=sink, category_name=category)
                )
        for category, sinks_list in methods_dict.items():
            for method in sorted(methods_list):
                fp.write(
                    REMEDIATION_METHOD_TEMPLATE
                    % dict(method_name=method, category_name=category)
                )
    console.print("")
    console.print(
        Panel(
            f"Sample remediation config file [bold]{remediation_file}[/bold] created successfully.\nEdit this file and include only the required methods.\nThen, to use this remediation config perform the below steps",
            title="ShiftLeft Remediation Config Generator",
            expand=False,
        )
    )
    md = Markdown(
        f"""
```
# Perform a dry run to validate this config file
sl remediation dry-run --config {remediation_file} --app {app_name}
# Include this file with sl analyze
sl analyze --remediation-config {remediation_file} --app {app_name} ...
```
"""
    )
    console.print(md)
    console.print(
        Panel(
            f"Using this remediation config file as-is would suppress all findings for {app_name}!",
            title="NOTE",
            expand=False,
        )
    )


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
            for sink in sorted(sinks_list):
                fp.write(CHECK_METHOD_TEMPLATE % dict(method_name=sink))
        fp.write("#" * 79 + "\n\n")
        fp.write("#" * 79 + "\n")
        fp.write("# All methods (Uncomment as needed) #\n")
        fp.write("#" * 79 + "\n")
        for method in sorted(methods_list):
            fp.write("# " + CHECK_METHOD_TEMPLATE % dict(method_name=method))
    console.print(
        Panel(
            f"Sample policy file [bold]{policy_file}[/bold] created successfully.\nEdit this file and include only the required methods.\nThen, to use this policy perform the below steps as a ShiftLeft administrator",
            title="ShiftLeft Policy Generator",
            expand=False,
        )
    )
    policy_label = app_name.replace("-", "_")
    md = Markdown(
        f"""
```
sl policy validate {policy_file}
sl policy push {policy_label} {policy_file}
sl policy assignment set --project {app_name} {org_id}/{policy_label}:latest

# Or to make the policy the default for your organization
# sl policy assignment set {org_id}/{policy_label}:latest
```
"""
    )
    console.print(md)
    console.print(f"Then perform sl analyze as normal\n")
    console.print(
        Panel(
            f"Using this policy file as-is would suppress all findings for {app_name}!",
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
    parser.add_argument(
        "--remediation",
        dest="remediation_file",
        help="Remediation config filename to generate",
        default="remediation.yaml",
    )
    parser.add_argument(
        "--vars-file",
        dest="vars_file",
        help="Variables filename",
        default="category_vars.txt",
    )
    parser.add_argument(
        "--cat-routes-file",
        dest="routes_file",
        help="Category routes filename",
        default="category_routes.txt",
    )
    return parser.parse_args()


def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    return obj


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
    (
        sources_dict,
        sinks_dict,
        methods_list,
        methods_dict,
        files_loc_list,
        vars_dict,
        category_route_dict,
    ) = start_analysis(org_id, args.app_name, args.version)
    if vars_dict:
        with open(args.vars_file, mode="w") as vfp:
            json.dump(vars_dict, vfp, indent=2, default=set_default)
            console.print(f"Stored category variables in [bold]{args.vars_file}[/bold]")
    if category_route_dict:
        with open(args.routes_file, mode="w") as rfp:
            json.dump(category_route_dict, rfp, indent=2, default=set_default)
            console.print(
                f"Stored category http routes in [bold]{args.routes_file}[/bold]"
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
    create_remediation(
        org_id,
        args.app_name,
        sources_dict,
        sinks_dict,
        methods_dict,
        files_loc_list,
        args.remediation_file,
    )
