#/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

CACHE_DIR=$HOME/.cache/sl-deploy
REPO_CLONE_DIR=$CACHE_DIR/sources
mkdir -p $CACHE_DIR $REPO_CLONE_DIR $CACHE_DIR/all_repos
LANG=$1
CONFIRMATION=$2
WORKFLOW_TEMPLATES_DIR=$SCRIPT_DIR/workflow_templates
SL_PR_BRANCH=feature/shiftleft-core

download_gh_cli() {
    if ! [ -x "$(command -v gh)" ]; then
        echo "About to download GitHub cli"
        curl -LO https://github.com/cli/cli/releases/download/v2.20.2/gh_2.20.2_linux_amd64.tar.gz $CACHE_DIR/
        tar -xvf $CACHE_DIR/gh_2.20.2_linux_amd64.tar.gz
        chmod +x $CACHE_DIR/gh_2.20.2_linux_amd64/bin/gh
        sudo install $CACHE_DIR/gh_2.20.2_linux_amd64/bin/gh /usr/local/bin/
    fi
}

download_sl() {
    if ! [ -x "$(command -v sl)" ]; then
        echo "About to download ShiftLeft cli"
        curl https://cdn.shiftleft.io/download/sl > $CACHE_DIR/sl
        sudo install $CACHE_DIR/sl /usr/local/bin/
        sl auth
    fi
}

check_auth() {
    gh auth status
    if [ $? != 0 ]; then
        echo "If prompted to login, choose your GitHub server and SSH as the protocol"
        gh auth login
    fi
}

collect_repos() {
    echo "Collecting repos list from GitHub and storing under ${CACHE_DIR}/all_repos"
    GH_ARGS="id,name,owner,description,primaryLanguage,languages,url,sshUrl,isEmpty,isFork,isPrivate,isTemplate,pushedAt,updatedAt"
    gh repo list -l java --no-archived --json $GH_ARGS > $CACHE_DIR/all_repos/java.json
    gh repo list -l javascript --no-archived --json $GH_ARGS > $CACHE_DIR/all_repos/js.json
    gh repo list -l dotnet --no-archived --json $GH_ARGS > $CACHE_DIR/all_repos/csharp.json
    gh repo list -l go --no-archived --json $GH_ARGS > $CACHE_DIR/all_repos/go.json
    gh repo list -l python --no-archived --json $GH_ARGS > $CACHE_DIR/all_repos/python.json
    gh repo list -l scala --no-archived --json $GH_ARGS > $CACHE_DIR/all_repos/scala.json
    gh repo list -l c --no-archived --json $GH_ARGS > $CACHE_DIR/all_repos/c.json
    ls -lh $CACHE_DIR/all_repos
}

clone_single_repo() {
    repo_name=$1
    lang=$2
    if [ ! -e "$REPO_CLONE_DIR/$repo_name" ]; then
        echo "About to clone $repo_name to $REPO_CLONE_DIR/$repo_name"
        gh repo clone $repo_name $REPO_CLONE_DIR/$repo_name
    fi
    if [ -e "$REPO_CLONE_DIR/$repo_name" ]; then
        mkdir -p $REPO_CLONE_DIR/$repo_name/.github/workflows
        if [ ! -e "$REPO_CLONE_DIR/$repo_name/.github/workflows/sl-${lang}.yml" ]; then
            cd $REPO_CLONE_DIR/$repo_name
            git switch --create $SL_PR_BRANCH || true
            git pull origin $SL_PR_BRANCH || true
            if [ -e "$WORKFLOW_TEMPLATES_DIR/sl-${lang}.yml" ]; then
                cp $WORKFLOW_TEMPLATES_DIR/sl-${lang}.yml $REPO_CLONE_DIR/$repo_name/.github/workflows/
            else
                echo "Unable to locate workflow template $WORKFLOW_TEMPLATES_DIR/sl-${lang}.yml"
            fi
            git add .github/workflows/
            git commit -a -m "Adds ShiftLeft CORE code analysis"
            git push origin $SL_PR_BRANCH -f
            gh pr create --repo $repo_name --base master --head $SL_PR_BRANCH --title "Pull Request to add ShiftLeft CORE scans" --body-file $WORKFLOW_TEMPLATES_DIR/pr-body.md
        else
            echo "$repo_name is already enabled for ShiftLeft CORE"
        fi
    else
        echo "Unable to clone repo $repo_name. Ensure your token has permission to clone repos and create pull requests to deploy ShiftLeft"
    fi
}

cleanup_repos() {
    if [ -e "$REPO_CLONE_DIR" ]; then
        rm -rf $REPO_CLONE_DIR
    fi
}

download_gh_cli
check_auth
download_sl
# collect_repos
clone_single_repo HooliCorp/java-sec-code java
# cleanup_repos
