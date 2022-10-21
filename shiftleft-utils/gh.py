import os

from common import LOG
from github import Github


def get_user(gh):
    return gh.get_user()


def get_context():
    return {
        "repoWorkspace": os.getenv("GITHUB_WORKSPACE"),
        "runID": os.getenv("GITHUB_RUN_ID"),
        "repoFullname": os.getenv("GITHUB_REPOSITORY"),
        "triggerEvent": os.getenv("GITHUB_EVENT_NAME"),
        "headRef": os.getenv("GITHUB_HEAD_REF"),
        "baseRef": os.getenv("GITHUB_BASE_REF"),
        "githubToken": os.getenv("GITHUB_TOKEN"),
        "commitSHA": os.getenv("GITHUB_SHA"),
        "workflow": os.getenv("GITHUB_WORKFLOW"),
        "home": os.getenv("HOME"),
        "actionId": os.getenv("GITHUB_ACTION"),
        "trigger": os.getenv("GITHUB_ACTOR"),
        "triggerBranchTag": os.getenv("GITHUB_REF"),
        "triggerPath": os.getenv("GITHUB_EVENT_PATH"),
        "serverUrl": os.getenv("GITHUB_SERVER_URL"),
        "graphqlUrl": os.getenv("GITHUB_GRAPHQL_URL"),
    }


def get_workflow(g, github_context):
    if not github_context.get("repoFullname") or not github_context.get("runID"):
        return
    repo = g.get_repo(github_context.get("repoFullname"))
    runID = github_context.get("runID")
    if runID and runID.isdigit():
        runID = int(runID)
    try:
        return repo.get_workflow_run(runID)
    except Exception as e:
        LOG.error(e)
        return None


def client():
    gh = None
    if not os.getenv("GITHUB_TOKEN"):
        LOG.debug(
            "Please ensure GITHUB_TOKEN environment variable is set with permissions to read/write to pull requests"
        )
        return None
    try:
        # Try GitHub enterprise first
        # Variables beginning with GITHUB_ cannot be overridden
        server_url = os.getenv("GH_SERVER_URL")
        if not server_url:
            server_url = os.getenv("GITHUB_SERVER_URL")
        if server_url and server_url != "https://github.com":
            if not server_url.startswith("http"):
                server_url = "https://" + server_url
            if not server_url.endswith("/"):
                server_url = server_url + "/"
            LOG.debug("Authenticating to GitHub Enterprise server: " + server_url)
            gh = Github(
                base_url=f"{server_url}api/v3",
                login_or_token=os.getenv("GITHUB_TOKEN"),
            )
        else:
            # Fallback to public GitHub
            gh = Github(os.getenv("GITHUB_TOKEN"))
        user = get_user(gh)
        if not user:
            return None
    except Exception as e:
        LOG.error(e)
        return None
    return gh


def annotate(annotated_findings, scan_info, changed_files_only=False):
    github_context = get_context()
    scan_version = scan_info.get("version")
    g = client()
    if not g:
        LOG.debug("Unable to authenticate with GitHub. Skipping PR annotation")
        return
    workflow_run = get_workflow(g, github_context)
    if not workflow_run:
        LOG.debug("Unable to find the workflow run for this invocation")
        return
    pull_requests = workflow_run.pull_requests
    if not pull_requests:
        LOG.debug("No Pull Requests are associated with this workflow run")
        return
    for pr in pull_requests:
        commits = pr.get_commits()
        last_commit = None
        changed_files = None
        if commits:
            last_commit = commits.reversed[0]
        elif github_context.get("commitSHA"):
            last_commit = g.get_commit(github_context.get("commitSHA"))
        if not last_commit:
            continue
        changed_files = [f.filename for f in last_commit.files]
        for f in annotated_findings:
            severity = f.get("severity")
            version_first_seen = f.get("version_first_seen")
            # Ignore legacy findings
            # if f.get("version_first_seen") != scan_version:
            #     continue
            last_location = f.get("last_location")
            if last_location:
                tmpA = last_location.split(":")
                last_location_fname = tmpA[0]
                last_location_lineno = int(tmpA[-1])
                best_fix = f.get("best_fix").replace("\\n", "\n")
                # Automatically prefix src/main/java or src/main/scala
                if last_location_fname.endswith(
                    ".java"
                ) and not last_location_fname.startswith("src"):
                    last_location_fname = "src/main/java/" + last_location_fname
                if last_location_fname.endswith(
                    ".scala"
                ) and not last_location_fname.startswith("src"):
                    last_location_fname = "src/main/scala/" + last_location_fname
                body = f"""{f.get("title")}
**Location:** {github_context.get("serverUrl")}/{github_context.get("repoFullname")}/blob/{github_context.get("commitSHA")}/{last_location_fname}#L{last_location_lineno}
{best_fix}
**Finding Link:** {f.get("deep_link")}
"""
                if changed_files_only:
                    if last_location_fname in changed_files:
                        last_commit.create_comment(
                            body, last_location_lineno, last_location_fname
                        )
                        LOG.debug(
                            f"Added comment to {last_location_fname} {last_location_lineno}"
                        )
                else:
                    last_commit.create_comment(
                        body, last_location_lineno, last_location_fname
                    )
                    LOG.debug(
                        f"Added comment to {last_location_fname} {last_location_lineno}"
                    )
