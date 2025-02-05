# based on https://github.com/pombredanne/joern2sarif
import datetime
import io
import json
import os
import pathlib
import re
import uuid
from string import capwords
from urllib.parse import quote_plus, urlparse

import sarif_om as om
from jschema_to_python.to_json import to_json

from issue import issue_from_dict

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


repo_url_prefixes = ["http", "git", "ssh"]


def find_repo_details(src_dir=None):
    """Method to find repo details such as url, sha etc
    This will be populated into versionControlProvenance attribute

    :param src_dir: Source directory
    """
    # See if repository uri is specified in the config
    repositoryName = None
    repositoryUri = ""
    revisionId = ""
    branch = ""
    invokedBy = ""
    pullRequest = False
    gitProvider = ""
    ciProvider = ""
    """
    Since CI servers typically checkout repo in detached mode, we need to rely on environment
    variables as a starting point to find the repo details. To make matters worse, since we
    run the tools inside a container these variables should be passed as part of the docker run
    command. With native integrations such as GitHub action and cloudbuild this could be taken
    care by our builders.

    Env variables detection for popular CI server is implemented here anyways. But they are effective
    only in few cases.

    Azure pipelines - https://docs.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml
    BitBucket - https://confluence.atlassian.com/bitbucket/environment-variables-in-bitbucket-pipelines-794502608.html
    GitHub actions - https://help.github.com/en/actions/automating-your-workflow-with-github-actions/using-environment-variables
    Google CloudBuild - https://cloud.google.com/cloud-build/docs/configuring-builds/substitute-variable-values
    CircleCI - https://circleci.com/docs/2.0/env-vars/#built-in-environment-variables
    Travis - https://docs.travis-ci.com/user/environment-variables/#default-environment-variables
    AWS CodeBuild - https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html
    GitLab - https://docs.gitlab.com/ee/ci/variables/predefined_variables.html
    Jenkins - https://jenkins.io/doc/book/pipeline/jenkinsfile/#using-environment-variables
    """
    for key, value in os.environ.items():
        # Check REPOSITORY_URL first followed CI specific vars
        # Some CI such as GitHub pass only the slug instead of the full url :(
        if not gitProvider or not ciProvider:
            if key.startswith("GITHUB_"):
                if key == "GITHUB_REPOSITORY":
                    gitProvider = "github"
                if key == "GITHUB_ACTION":
                    ciProvider = "github"
            elif key.startswith("GITLAB_"):
                gitProvider = "gitlab"
                if key == "GITLAB_CI":
                    ciProvider = "gitlab"
            elif key.startswith("BITBUCKET_"):
                gitProvider = "bitbucket"
                if key == "BITBUCKET_BUILD_NUMBER":
                    ciProvider = "bitbucket"
            elif key.startswith("CIRCLE_"):
                ciProvider = "circle"
            elif key.startswith("TRAVIS_"):
                ciProvider = "travis"
            elif key.startswith("CODEBUILD_"):
                ciProvider = "codebuild"
            elif key.startswith("BUILD_REQUESTEDFOREMAIL"):
                ciProvider = "azure"
            elif key.startswith("JENKINS_"):
                ciProvider = "jenkins"
        if not repositoryName:
            if key in [
                "BUILD_REPOSITORY_NAME",
                "GITHUB_REPOSITORY",
                "BITBUCKET_REPO_SLUG",
                "REPO_NAME",
                "CIRCLE_PROJECT_REPONAME",
                "TRAVIS_REPO_SLUG",
                "CI_PROJECT_NAME",
            ]:
                if "/" in value:
                    repositoryName = value.split("/")[-1]
                else:
                    repositoryName = value
        if not repositoryUri:
            if key in [
                "REPOSITORY_URL",
                "BUILD_REPOSITORY_URI",
                "GITHUB_REPOSITORY",
                "BITBUCKET_GIT_HTTP_ORIGIN",
                "REPO_NAME",
                "CIRCLE_REPOSITORY_URL",
                "TRAVIS_REPO_SLUG",
                "CODEBUILD_SOURCE_REPO_URL",
                "CI_REPOSITORY_URL",
            ]:
                repositoryUri = value
        if key in [
            "COMMIT_SHA",
            "BUILD_SOURCEVERSION",
            "BITBUCKET_COMMIT",
            "GITHUB_SHA",
            "CIRCLE_SHA1",
            "TRAVIS_COMMIT",
            "CODEBUILD_SOURCE_VERSION",
            "CI_COMMIT_SHA",
        ]:
            revisionId = value
        if key in [
            "BRANCH",
            "BUILD_SOURCEBRANCH",
            "BITBUCKET_BRANCH",
            "GITHUB_REF",
            "BRANCH_NAME",
            "CIRCLE_BRANCH",
            "TRAVIS_BRANCH",
            "CI_COMMIT_REF_NAME",
        ]:
            branch = value
        if key in [
            "BUILD_REQUESTEDFOREMAIL",
            "GITHUB_ACTOR",
            "PROJECT_ID",
            "CIRCLE_USERNAME",
            "GITLAB_USER_EMAIL",
        ]:
            invokedBy = value
        if key.startswith("CI_MERGE_REQUEST"):
            pullRequest = True
    if branch.startswith("refs/pull"):
        pullRequest = True
        branch = branch.replace("refs/pull/", "")
    # Cleanup the variables
    branch = branch.replace("refs/heads/", "")
    if repositoryUri:
        repositoryUri = repositoryUri.replace(
            "git@github.com:", "https://github.com/"
        ).replace(".git", "")
        # Is it a repo slug?
        repo_slug = True
        repositoryUri = sanitize_url(repositoryUri)
        for pref in repo_url_prefixes:
            if repositoryUri.startswith(pref):
                repo_slug = False
                break
        if not repo_slug:
            if "vs-ssh" in repositoryUri:
                repo_slug = False
        # For repo slug just assume github for now
        if repo_slug:
            repositoryUri = "https://github.com/" + repositoryUri
    if not repositoryName and repositoryUri:
        repositoryName = os.path.basename(repositoryUri)
    if not gitProvider:
        if "github" in repositoryUri:
            gitProvider = "github"
        if "gitlab" in repositoryUri:
            gitProvider = "gitlab"
        if "atlassian" in repositoryUri or "bitbucket" in repositoryUri:
            gitProvider = "bitbucket"
        if "azure" in repositoryUri or "visualstudio" in repositoryUri:
            gitProvider = "azure"
            if not ciProvider:
                ciProvider = "azure"
        if not gitProvider and "tfs" in repositoryUri:
            gitProvider = "tfs"
            ciProvider = "tfs"
    return {
        "gitProvider": gitProvider,
        "ciProvider": ciProvider,
        "repositoryName": "" if not repositoryName else repositoryName,
        "repositoryUri": repositoryUri,
        "revisionId": revisionId,
        "branch": branch,
        "invokedBy": invokedBy,
        "pullRequest": pullRequest,
    }


def sanitize_url(url):
    """
    Method to sanitize url to remove credentials and tokens

    :param url: URL to sanitize
    :return: sanitized url
    """
    result = urlparse(url)
    username = result.username
    password = result.password
    sens_str = ""
    if username and password:
        sens_str = "{}:{}@".format(username, password)
    url = url.replace(sens_str, "")
    if password:
        url = url.replace(password, "")
    return url


def convert_dataflow(working_dir, dataflows):
    """
    Convert dataflow into a simpler source and sink format for better representation in SARIF based viewers

    :param dataflows: List of dataflows from Inspect
    :return List of filename and location
    """
    if not dataflows:
        return None
    loc_list = []
    for flow in dataflows:
        location = flow.get("location")
        if not location.get("file_name") or not location.get("line_number"):
            continue
        loc_list.append(
            {
                "filename": os.path.join(working_dir, location.get("file_name")),
                "line_number": location.get("line_number"),
            }
        )
    return loc_list


def extract_from_file(
    tool_name, tool_args, working_dir, report_file, file_path_list=None
):
    """Extract properties from reports

    :param tool_name: tool name
    :param tool_args: tool args
    :param working_dir: Working directory
    :param report_file: Report file
    :param file_path_list: Full file path for any manipulation

    :return issues, metrics, skips information
    """
    issues = []
    # If the tools did not produce any result do not crash
    if not os.path.isfile(report_file):
        return issues
    extn = pathlib.PurePosixPath(report_file).suffix

    with io.open(report_file, "r") as rfile:
        if extn == ".json":
            try:
                report_data = json.load(rfile)
            except json.decoder.JSONDecodeError as je:
                return issues

            data_to_use = report_data
            # Is this raw json
            if report_data.get("ok"):
                response = report_data.get("response")
                if response:
                    data_to_use = {
                        response.get("scan", {}).get("app"): response.get(
                            "findings"
                        )
                    }
            for k, v in data_to_use.items():
                if not v:
                    continue
                for vuln in v:
                    location = {}
                    codeflows = []
                    vuln_type = vuln.get("type")
                    if vuln_type not in ("extscan", "vuln", "secret", "oss_vuln"):
                        continue
                    details = vuln.get("details", {})
                    file_locations = details.get("file_locations", [])
                    tags = vuln.get("tags", [])
                    internal_id = vuln.get("internal_id")
                    tmpA = internal_id.split("/")
                    rule_id = tmpA[0]
                    fingerprint = tmpA[-1]
                    score = ""
                    cvss_tag = [t for t in tags if t.get("key") == "cvss_score"]
                    if cvss_tag:
                        score = cvss_tag[0].get("value")
                    if vuln_type == "extscan":
                        location = {
                            "filename": os.path.join(
                                working_dir, details.get("fileName")
                            ),
                            "line_number": details.get("lineNumber"),
                        }
                        codeflows.append(location)
                    elif vuln_type == "oss_vuln":
                        location_tag = [t for t in tags if t.get("key") == "location"]
                        if len(location_tag) == 0:
                            location = {
                                "filename": "NA",
                                "line_number": "NA"
                            }
                        else:
                            sbom_location = location_tag[0].get("value").split('#')
                            location = {
                                "filename": sbom_location[0],
                                "line_number": sbom_location[1]
                            }
                    elif file_locations:
                        for floc in file_locations:
                            flocArr = floc.split(":")
                            codeflows.append(
                                {
                                    "filename": os.path.join(
                                        working_dir, flocArr[0]
                                    ),
                                    "line_number": flocArr[1],
                                }
                            )
                        location = codeflows[-1]
                    if not location and details.get("dataflow"):
                        dataflows = details.get("dataflow").get("list")
                        if dataflows:
                            location_list = convert_dataflow(working_dir, dataflows)
                            # Take the sink
                            if location_list:
                                codeflows = location_list
                                location = location_list[-1]
                    if not location and details.get("fileName") and details.get("lineNumber"):
                        location = {
                            "filename": details.get("fileName"),
                            "line_number": details.get("lineNumber")
                        }
                    issues.append(
                        {
                            "rule_id": rule_id,
                            "title": vuln["title"],
                            "short_description": vuln["category"],
                            "description": vuln["description"],
                            "score": score,
                            "severity": vuln["severity"],
                            "line_number": location.get("line_number"),
                            "filename": location.get("filename"),
                            "first_found": vuln["version_first_seen"],
                            "issue_confidence": "HIGH",
                            "fingerprint": fingerprint,
                            "codeflows": codeflows,
                        }
                    )
    return issues


def convert_file(
    tool_name,
    tool_args,
    working_dir,
    report_file,
    converted_file,
    file_path_list=None,
):
    """Convert report file

    :param tool_name: tool name
    :param tool_args: tool args
    :param working_dir: Working directory
    :param report_file: Report file
    :param converted_file: Converted file
    :param file_path_list: Full file path for any manipulation

    :return serialized_log: SARIF output data
    """
    issues = extract_from_file(
        tool_name, tool_args, working_dir, report_file, file_path_list
    )
    return report(
        tool_name=tool_name,
        tool_args=tool_args,
        working_dir=working_dir,
        issues=issues,
        crep_fname=converted_file,
        file_path_list=file_path_list,
    )


def report(
    tool_name="joern",
    tool_args=["--script", "oc_scripts/scan.sc"],
    working_dir="",
    issues=None,
    crep_fname="joern-report.sarif",
    file_path_list=None,
):
    """Prints issues in SARIF format

    :param tool_name: tool name
    :param tool_args: Args used for the tool
    :param working_dir: Working directory
    :param issues: issues data
    :param crep_fname: The output file name
    :param file_path_list: Full file path for any manipulation

    :return serialized_log: SARIF output data
    """
    if not tool_args:
        tool_args = []
    tool_args_str = tool_args
    if isinstance(tool_args, list):
        tool_args_str = " ".join(tool_args)
    repo_details = find_repo_details(working_dir)
    log_uuid = str(uuid.uuid4())
    run_uuid = str(uuid.uuid4())

    # working directory to use in the log
    WORKSPACE_PREFIX = os.getenv("WORKSPACE", None)
    wd_dir_log = WORKSPACE_PREFIX if WORKSPACE_PREFIX is not None else working_dir
    driver_name = "Qwiet preZero"
    information_uri = "https://qwiet.ai"
    # Construct SARIF log
    log = om.SarifLog(
        schema_uri="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version="2.1.0",
        inline_external_properties=[
            om.ExternalProperties(guid=log_uuid, run_guid=run_uuid)
        ],
        runs=[
            om.Run(
                automation_details=om.RunAutomationDetails(
                    guid=log_uuid,
                    description=om.Message(
                        text=f"Static Analysis Security Test results using {tool_name}"
                    ),
                ),
                tool=om.Tool(
                    driver=om.ToolComponent(
                        name=driver_name,
                        information_uri=information_uri,
                        full_name=driver_name,
                        version="1.0.0",
                    )
                ),
                invocations=[
                    om.Invocation(
                        end_time_utc=datetime.datetime.utcnow().strftime(TS_FORMAT),
                        execution_successful=True,
                        working_directory=om.ArtifactLocation(uri=to_uri(wd_dir_log)),
                    )
                ],
                conversion={
                    "tool": om.Tool(driver=om.ToolComponent(name=tool_name)),
                    "invocation": om.Invocation(
                        execution_successful=True,
                        command_line=tool_args_str,
                        arguments=tool_args,
                        working_directory=om.ArtifactLocation(uri=to_uri(wd_dir_log)),
                        end_time_utc=datetime.datetime.utcnow().strftime(TS_FORMAT),
                    ),
                },
                version_control_provenance=[
                    om.VersionControlDetails(
                        repository_uri=repo_details["repositoryUri"],
                        branch=repo_details["branch"],
                        revision_id=repo_details["revisionId"],
                    )
                ],
            )
        ],
    )
    run = log.runs[0]
    add_results(tool_name, issues, run, file_path_list, working_dir)
    serialized_log = to_json(log)
    if crep_fname:
        with io.open(crep_fname, "w") as fileobj:
            fileobj.write(serialized_log)
    return serialized_log


def add_results(tool_name, issues, run, file_path_list=None, working_dir=None):
    """Method to convert issues into results schema

    :param tool_name: tool name
    :param issues: Issues found
    :param run: Run object
    :param file_path_list: Full file path for any manipulation
    :param working_dir: Working directory
    """
    if run.results is None:
        run.results = []

    rules = {}
    rule_indices = {}

    for issue in issues:
        result = create_result(
            tool_name,
            issue,
            rules,
            rule_indices,
            file_path_list,
            working_dir,
        )
        if result:
            run.results.append(result)
    if len(rules) > 0:
        run.tool.driver.rules = list(rules.values())


def fix_filename(working_dir, filename):
    """Method to prefix filename based on workspace

    :param working_dir: Working directory
    :param filename: File name to fix
    """
    WORKSPACE_PREFIX = os.getenv("WORKSPACE", None)
    if working_dir:
        # Convert to full path only if the user wants
        if WORKSPACE_PREFIX is None and not filename.startswith(working_dir):
            filename = os.path.join(working_dir, filename)
        if WORKSPACE_PREFIX is not None:
            # Make it relative path
            if WORKSPACE_PREFIX == "":
                filename = re.sub(r"^" + working_dir + "/", WORKSPACE_PREFIX, filename)
            elif not filename.startswith(working_dir):
                filename = os.path.join(WORKSPACE_PREFIX, filename)
            else:
                filename = re.sub(r"^" + working_dir, WORKSPACE_PREFIX, filename)
    return filename


def create_result(tool_name, issue, rules, rule_indices, file_path_list, working_dir):
    """Method to convert a single issue into result schema with rules

    :param tool_name: tool name
    :param issue: Issues object
    :param rules: List of rules
    :param rule_indices: Indices of referred rules
    :param file_path_list: Full file path for any manipulation
    :param working_dir: Working directory
    """
    if isinstance(issue, dict):
        issue = issue_from_dict(issue)

    issue_dict = issue.as_dict()
    rule, rule_index = create_or_find_rule(tool_name, issue_dict, rules, rule_indices)

    # Substitute workspace prefix
    # Override file path prefix with workspace
    filename = fix_filename(working_dir, issue_dict["filename"])
    physical_location = om.PhysicalLocation(
        artifact_location=om.ArtifactLocation(uri=to_uri(filename))
    )

    add_region_and_context_region(
        physical_location, issue_dict["line_number"], issue_dict["code"]
    )
    thread_flows_list = []
    issue_severity = issue_dict["issue_severity"]
    fingerprint = {"evidenceFingerprint": issue_dict["line_hash"]}
    if issue_dict.get("codeflows"):
        thread_locations = []
        for cf in issue_dict.get("codeflows"):
            if cf.get("filename") and cf.get("line_number"):
                thread_physical_location = om.PhysicalLocation(
                    artifact_location=om.ArtifactLocation(
                        uri=to_uri(fix_filename(working_dir, cf["filename"]))
                    ),
                    region=om.Region(
                        start_line=int(cf["line_number"]),
                        snippet=om.ArtifactContent(text=""),
                    ),
                )
                thread_locations.append(
                    {
                        "location": om.Location(
                            physical_location=thread_physical_location
                        )
                    }
                )
        if thread_locations:
            thread_flows_list.append(om.ThreadFlow(locations=thread_locations))
    result = om.Result(
        rule_id=rule.id,
        rule_index=rule_index,
        message=om.Message(
            text=issue_dict["title"].replace("`", ""),
            markdown=issue_dict["title"],
        ),
        level=level_from_severity(issue_severity),
        locations=[om.Location(physical_location=physical_location)],
        partial_fingerprints=fingerprint,
        properties={
            "issue_confidence": issue_dict["issue_confidence"],
            "issue_severity": issue_severity,
            "issue_tags": issue_dict.get("tags", {}),
        },
        baseline_state="unchanged" if issue_dict["first_found"] else "new",
    )
    # Add thread flows if available
    if thread_flows_list:
        result.code_flows = [om.CodeFlow(thread_flows=thread_flows_list)]
    return result


def level_from_severity(severity):
    """Converts tool's severity to the 4 level
    suggested by SARIF
    """
    if severity == "CRITICAL":
        return "error"
    elif severity == "HIGH":
        return "error"
    elif severity == "MEDIUM":
        return "warning"
    elif severity == "LOW":
        return "note"
    else:
        return "warning"


def add_region_and_context_region(physical_location, line_number, code):
    """This adds the region information for displaying the code snippet

    :param physical_location: Points to file
    :param line_number: Line number suggested by the tool
    :param code: Source code snippet
    """
    first_line_number, snippet_lines = parse_code(code)
    # Ensure start line is always non-zero
    if first_line_number == 0:
        first_line_number = 1
    end_line_number = first_line_number + len(snippet_lines) - 1
    if end_line_number < first_line_number:
        end_line_number = first_line_number + 3
    index = line_number - first_line_number
    snippet_line = ""
    if line_number == 0:
        line_number = 1
    if snippet_lines and len(snippet_lines) > index:
        if index > 0:
            snippet_line = snippet_lines[index]
        else:
            snippet_line = snippet_lines[0]
    if snippet_line.strip().replace("\n", "") == "":
        snippet_line = ""
    physical_location.region = om.Region(
        start_line=line_number, snippet=om.ArtifactContent(text=snippet_line)
    )
    if snippet_lines:
        physical_location.context_region = om.Region(
            start_line=first_line_number,
            end_line=end_line_number,
            snippet=om.ArtifactContent(text="".join(snippet_lines)),
        )


def parse_code(code):
    """Method to parse the code to extract line number and snippets"""
    code_lines = code.split("\n")

    # The last line from the split has nothing in it; it's an artifact of the
    # last "real" line ending in a newline. Unless, of course, it doesn't:
    last_line = code_lines[len(code_lines) - 1]

    last_real_line_ends_in_newline = False
    if len(last_line) == 0:
        code_lines.pop()
        last_real_line_ends_in_newline = True

    snippet_lines = []
    first = True
    first_line_number = 1
    for code_line in code_lines:
        number_and_snippet_line = code_line.split(" ", 1)
        if first:
            first_line_number = int(number_and_snippet_line[0])
            first = False
        if len(number_and_snippet_line) > 1:
            snippet_line = number_and_snippet_line[1] + "\n"
            snippet_lines.append(snippet_line)

    if not last_real_line_ends_in_newline:
        last_line = snippet_lines[len(snippet_lines) - 1]
        snippet_lines[len(snippet_lines) - 1] = last_line[: len(last_line) - 1]

    return first_line_number, snippet_lines


def get_rule_short_description(tool_name, rule_id, test_name, issue_dict):
    """
    Constructs a short description for the rule

    :param tool_name:
    :param rule_id:
    :param test_name:
    :param issue_dict:
    :return:
    """
    if issue_dict.get("short_description"):
        return issue_dict.get("short_description")
    return "Rule {} from {}.".format(rule_id, tool_name)


def get_rule_full_description(tool_name, rule_id, test_name, issue_dict):
    """
    Constructs a full description for the rule

    :param tool_name:
    :param rule_id:
    :param test_name:
    :param issue_dict:
    :return:
    """
    issue_text = issue_dict.get("issue_text", "")
    # Extract just the first line alone
    if issue_text:
        issue_text = issue_text.split("\n")[0]
    if not issue_text.endswith("."):
        issue_text = issue_text + "."
    return issue_text


def get_help(format, tool_name, rule_id, test_name, issue_dict):
    """
    Constructs a full description for the rule

    :param format: text or markdown
    :param tool_name:
    :param rule_id:
    :param test_name:
    :param issue_dict:
    :return: Help text
    """
    issue_text = issue_dict.get("issue_text", "")
    if format == "text":
        issue_text = issue_text.replace("`", "")
    return issue_text


def get_url(tool_name, rule_id, test_name, issue_dict):
    if issue_dict.get("test_ref_url"):
        return issue_dict.get("test_ref_url")
    rule_id = quote_plus(rule_id)
    if rule_id and rule_id.startswith("CWE"):
        return "https://cwe.mitre.org/data/definitions/%s.html" % rule_id.replace(
            "CWE-", ""
        )
    if issue_dict.get("cwe_category"):
        return "https://cwe.mitre.org/data/definitions/%s.html" % issue_dict.get(
            "cwe_category"
        ).replace("CWE-", "")
    return "https://docs.shiftleft.io/ngsast/product-info/coverage#vulnerabilities"


def create_or_find_rule(tool_name, issue_dict, rules, rule_indices):
    """Creates rules object for the rules section. Different tools make up
        their own id and names so this is identified on the fly

    :param tool_name: tool name
    :param issue_dict: Issue object that is normalized and converted
    :param rules: List of rules identified so far
    :param rule_indices: Rule indices cache

    :return rule and index
    """
    rule_id = issue_dict["test_id"]
    rule_name = issue_dict["test_name"]
    if rule_id == rule_name:
        rule_name = rule_name.lower().replace("_", " ")
    if rule_id == rule_name.lower():
        rule_name = f"{rule_name} rule"
    rule_name = capwords(rule_name).replace(" ", "")
    if rule_id in rules:
        return rules[rule_id], rule_indices[rule_id]
    precision = "very-high"
    issue_severity = issue_dict["issue_severity"]
    rule = om.ReportingDescriptor(
        id=rule_id,
        name=rule_name,
        short_description={
            "text": get_rule_short_description(
                tool_name, rule_id, issue_dict["test_name"], issue_dict
            )
        },
        full_description={
            "text": get_rule_full_description(
                tool_name, rule_id, issue_dict["test_name"], issue_dict
            )
        },
        help={
            "text": get_help(
                "text", tool_name, rule_id, issue_dict["test_name"], issue_dict
            ),
            "markdown": get_help(
                "markdown", tool_name, rule_id, issue_dict["test_name"], issue_dict
            ),
        },
        help_uri=get_url(tool_name, rule_id, issue_dict["test_name"], issue_dict),
        properties={
            "tags": [tool_name],
            "precision": precision,
        },
        default_configuration={"level": level_from_severity(issue_severity)},
    )

    index = len(rules)
    rules[rule_id] = rule
    rule_indices[rule_id] = index
    return rule, index


def to_uri(file_path):
    """Converts to file path to uri prefixed with file://

    :param file_path: File path to convert
    """
    if file_path.startswith("http"):
        return file_path
    if "\\" in file_path:
        if "/" in file_path:
            file_path = file_path.replace("/", "\\")
        pure_path = pathlib.PureWindowsPath(file_path)
    else:
        pure_path = pathlib.PurePath(file_path)
    if pure_path.is_absolute():
        return pure_path.as_uri()
    else:
        return pure_path.as_posix()  # Replace backslashes with slashes.
