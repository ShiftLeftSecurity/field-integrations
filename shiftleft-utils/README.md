# ShiftLeft Utils

Collection of scripts to help integrate ShiftLeft NextGen Analysis with your DevOps workflow.

## Usage

Install python 3 on the machine or vm running the scripts.

Clone the repo.

```bash
cd shiftleft-utils
pip install -r requirements.txt
```

Set the access token as an environment variable.

export SHIFTLEFT_ACCESS_TOKEN=long token from shiftleft

## Description of scripts

| Script       | Purpose                                                      |
| ------------ | ------------------------------------------------------------ |
| export.py    | Export NG SAST findings report to xml, json and SARIF format |
| stats.py     | Display stats for all apps based on last scan                |
| policygen.py | Generate policy file to suppress findings                    |

### Sample usages

Export findings of an app in json format

```bash
python export.py -f json -a <app name>
```

Export findings of an app in sarif format

```bash
python export.py -f sarif -a <app name>
```

NOTE: For jvm languages, we may have to fix the file path since the value returned by the API would not include prefix such as `src/main/java` or `src/main/scala`. To specify such custom prefix, set the environment variable `WORKSPACE`

```bash
WORKSPACE=<path to src/main/java> python export.py -f sarif -a <app name>
```

## License

Apache-2.0

## Known issues

```bash
urllib3.exceptions.LocationParseError: Failed to parse: https://www.shiftleft.io/api/v4/orgs/
```

To fix this error upgrade urllib3 package

```bash
pip3 install --upgrade urllib3
```
