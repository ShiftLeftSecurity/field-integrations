# ShiftLeft Utils

Collection of scripts to help integrate ShiftLeft NextGen Analysis with your DevOps workflow.

## Usage

Install python 3.9 or above on the machine or vm running the scripts.

Clone the repo and install the dependencies.

```bash
git clone https://github.com/ShiftLeftSecurity/field-integrations.git
cd shiftleft-utils
pip3 install -r requirements.txt
```

On Windows, non-admin users might see the below error. To workaround this, pass `--user` as shown.

`ERROR: Could not install packages due to an OSError: [WinError 5] Access is denied`

```
python -m pip install --upgrade pip --user
python -m pip install -r .\requirements.txt --user
```

On a Mac, use of [pyenv](https://github.com/pyenv/pyenv) is recommended.

Set the ShiftLeft access token as an environment variable SHIFTLEFT_ACCESS_TOKEN.

```
export SHIFTLEFT_ACCESS_TOKEN=long token from shiftleft
```

## Description of scripts

| Script                  | Purpose                                                           |
| ----------------------- | ----------------------------------------------------------------- |
| export.py               | Export NG SAST findings report to csv, xml, json and SARIF format |
| stats.py                | Display stats for all apps based on last scan                     |
| policygen.py            | Generate policy file to suppress findings                         |
| bulk_delete_projects.py | Delete projects from a file containing a list                     |
| bestfix.py              | Suggest best fix locations for key SAST findings for an app       |

### Sample usages

Collect summary stats for your organization

```bash
python3 stats.py
```

Include token name in the stats by querying runtime information api.

```
python3 stats.py --include-run-info
```

Collect detailed stats for your organization including sources, sinks, file locations, method names, and routes.

```bash
python3 stats.py --detailed
```

Collect stats for a specific branch across apps

```bash
python3 stats.py --detailed --branch main
```

Export findings of an app in csv format

```bash
python3 export.py -f csv -a <app name>
```

Export findings of an app in sarif format

```bash
python3 export.py -f sarif -a <app name>
```

NOTE: For jvm languages, we may have to fix the file path since the value returned by the API would not include prefix such as `src/main/java` or `src/main/scala`. To specify such custom prefix, set the environment variable `WORKSPACE`

```bash
WORKSPACE=<path to src/main/java> python export.py -f sarif -a <app name>
```

Find best fix locations for `vuln-spring` app with the source code under `/mnt/work/HooliCorp/vuln-spring`

```
python3 bestfix.py -a vuln-spring -s /mnt/work/HooliCorp/vuln-spring
```

To troubleshoot a scan and look for tips to improve the scan results and performance, pass `--troubleshoot` to bestfix.

```
python3 bestfix.py -a vuln-spring --troubleshoot -s /mnt/work/HooliCorp/vuln-spring
```

## License

Apache-2.0

## Known issues

```bash
urllib3.exceptions.LocationParseError: Failed to parse: https://app.shiftleft.io/api/v4/orgs/
```

To fix this error upgrade urllib3 package

```bash
pip3 install --upgrade urllib3
```
