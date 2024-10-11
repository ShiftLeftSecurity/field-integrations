import argparse
import json
import os
import requests
import sys
from rich.console import Console
from rich.theme import Theme
from common import extract_org_id, headers
import config

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

def get_sca_packages(org_id, app_id):
    """ Return the SCA packages for the given app
    :param org_id: Organization ID
    :param app_id: App ID
    """
    page_number = 1
    has_more = False
    sca_packages_url = f"https://{config.SHIFTLEFT_API_HOST}/api/v4/orgs/{org_id}/apps/{app_id}/sca/packages?page={page_number}&per_page=100"
    r = requests.get(sca_packages_url, headers=headers)
    if r.ok:
        raw_response = r.json().get("response")
        if raw_response.get("has_more"):
            has_more = True
        while has_more:
            page_number += 1
            sca_packages_url = f"https://{config.SHIFTLEFT_API_HOST}/api/v4/orgs/{org_id}/apps/{app_id}/sca/packages?page={page_number}&per_page=100"
            n = requests.get(sca_packages_url, headers=headers)
            if n.ok:
                has_more = n.json().get("response").get("has_more", False)
                raw_response["packages"].extend(n.json().get("response").get("packages"))
            else:
                console.print(
                    f"Unable to retrieve SCA packages for {app_id} due to {n.status_code} error"
                )
                return None

        packages_count = len(raw_response.get("packages"))    
        console.print(
            f"Retrieved {packages_count} SCA packages for {app_id}"
        )
        raw_response.pop("has_more")
        return raw_response
    else:
        console.print(
            f"Unable to retrieve SCA packages for {app_id} due to {r.status_code} error"
        )
        return None

def build_args():
    parser = argparse.ArgumentParser(description="Qwiet AI preZero SBOM report")
    parser.add_argument(
        "-a",
        "--app",
        dest="app_name",
        help="App name",
        default=config.SHIFTLEFT_APP,
    )
    parser.add_argument(
        "-f",
        "--format",
        dest="rformat",
        help="Report format",
        default="json",
        choices=["json"],
    )
    parser.add_argument(
        "-o",
        "--report_file",
        dest="report_file",
        help="Report filename",
        default="qwiet-sbom-report.json",
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

    args = build_args()

    sca_json = get_sca_packages(org_id, args.app_name)
    if not sca_json:
        console.print("Got NONE from get_sca_packages")
        sys.exit(1)

    with open(args.report_file, "w") as json_file:
        json.dump(sca_json, json_file, indent=4)

    console.print(f"SBOM report written to {args.report_file}")
