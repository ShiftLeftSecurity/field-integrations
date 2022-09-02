#! /bin/bash
# *** ENV Variables ***

# Set absolute path to working directory.
# "/home/user/projects/projectfolder" or "/home/user/projects/projectfolder/project.jar"
DOCKER_WORK_DIR="/Users/yusefsaraby/projects/testing" # <-- Update per comment above
DOCKER_IMAGE_NAME=shiftleft/core:latest

# User defined repositories
GO_REPO=https://github.com/ShiftLeftSecurity/shiftleft-go-demo.git
JAVA_REPO=https://github.com/ShiftLeftSecurity/shiftleft-java-demo.git
PYTHON_REPO=https://github.com/ShiftLeftSecurity/shiftleft-python-demo.git
JS_REPO=https://github.com/ShiftLeftSecurity/shiftleft-js-demo.git

ERR_NOT_FOUND=126
SUMMARY_GO=0
SUMMARY_JAVA=0
SUMMARY_PYTHON=0
SUMMARY_JS=0

# Variable Cleanup
## Remove trailing slash(es) if present
DOCKER_WORK_DIR="${DOCKER_WORK_DIR%/}"

# Check heck if Docker is installed
if ! [ -x "$(command -v docker)" ]; then
    echo "Install docker"
    exit $ERR_NOT_FOUND
fi

if [ -z "$SHIFTLEFT_ACCESS_TOKEN" ]; then
    echo "Did you run 'sl auth', or set the SHIFTLEFT_ACCESS_TOKEN environment variable?"
    exit $ERR_NOT_FOUND
fi

# Get the lastest docker image
docker pull $DOCKER_IMAGE_NAME

# $1: language (python, go, js, java)
# $2: absolute path to code or binaries
shiftleft_analyze_code() {
    echo "Will analyze $1 code at location $2"
    docker run --rm -e SHIFTLEFT_ACCESS_TOKEN -v "$2":/myvol -it $DOCKER_IMAGE_NAME sl analyze --wait --container $DOCKER_IMAGE_NAME --app shiftleft-js-demo "--$1" /myvol
}

# $1: absolute path to code or binaries
run_demo_go() {
    echo "Analyzing Go project: code at location $1"
    shiftleft_analyze_code "go" "$1"
    docker run --rm -e SHIFTLEFT_ACCESS_TOKEN -v "$1":/myvol -it $DOCKER_IMAGE_NAME /bin/bash -c "cd /myvol; go build; sl analyze --wait --container $DOCKER_IMAGE_NAME --app shiftleft-go-demo --go /myvol"
}

# $1: absolute path to code or binaries
run_demo_java() {
    echo "Analyzing JAVA project: code at location $1"
    shiftleft_analyze_code "java" "$1"
    docker run --rm -e SHIFTLEFT_ACCESS_TOKEN -v "$1":/myvol -it $DOCKER_IMAGE_NAME /bin/bash -c "cd /myvol; mvn clean package; sl analyze --wait --container $DOCKER_IMAGE_NAME --app shiftleft-java-demo --java /myvol/target/hello-shiftleft-0.0.1.jar"
}

# $1: absolute path to code or binaries
run_demo_python() {
    echo "Analyzing PYTHON project: code at location $1"
    shiftleft_analyze_code "python" "$1"
    docker run --rm -e SHIFTLEFT_ACCESS_TOKEN -v "$1":/myvol -it $DOCKER_IMAGE_NAME /bin/bash -c "cd /myvol; pip install -r requirements.txt; sl analyze --wait --container $DOCKER_IMAGE_NAME --app shiftleft-python-demo --python /myvol"
    # docker run --rm -e SHIFTLEFT_ACCESS_TOKEN -v "$1":/myvol -it $DOCKER_IMAGE_NAME /bin/bash -c "cd /myvol; pip install -r requirements.txt; sl analyze --wait --container $DOCKER_IMAGE_NAME --app shiftleft-python-demo --python /myvol; sl check-analysis --v2 --source scan.1  --target scan.2 --app $(basename $GO_REPO) --config /myvol/$REPO_NAME_PYTHON/shiftleft.yml"
}

# $1: Clone Command exit code
# $2: Repository language
# $3: Repository Clone URL
failed_to_clone() {
   # We exit in failed to clone, this usually means network or write perm issues, if one fails others are likely to
    echo "Failed to clone $2 repository from $3"
    echo "Continue"
    # exit "$1"
    return 0
}

# SL to analyze demo applications
 echo "************** GO *************"

 DOCKER_REPO_GO="$DOCKER_WORK_DIR/$(basename $GO_REPO)"

 git clone $GO_REPO "$DOCKER_REPO_GO" || failed_to_clone $? "go" $GO_REPO

 run_demo_go "$DOCKER_REPO_GO" || SUMMARY_GO=$?

 

 echo "************** JAVA *************"

 DOCKER_REPO_JAVA="$DOCKER_WORK_DIR/$(basename $JAVA_REPO)"

 git clone $JAVA_REPO "$DOCKER_REPO_JAVA" || failed_to_clone $? "java" $JAVA_REPO

 run_demo_java "$DOCKER_REPO_JAVA" || SUMMARY_JAVA=$?

 

 echo "************** PYTHON *************"

 REPO_NAME_PYTHON="$(basename $PYTHON_REPO)"

 DOCKER_REPO_PYTHON="$DOCKER_WORK_DIR/$REPO_NAME_PYTHON"

 git clone $PYTHON_REPO "$DOCKER_REPO_PYTHON" || failed_to_clone $? "java" $PYTHON_REPO

 run_demo_python "$DOCKER_REPO_PYTHON" || SUMMARY_PYTHON=$?

  
echo "************** JS *************"
DOCKER_REPO_JS="$DOCKER_WORK_DIR/$(basename $JS_REPO)"
git clone $JS_REPO "$DOCKER_REPO_JS" || failed_to_clone $? "java" $JS_REPO
shiftleft_analyze_code "js" "$DOCKER_REPO_JS" || SUMMARY_JS=$?


echo "Summary:"
if [ $SUMMARY_GO -eq 0 ]; then
    echo "(✔) GO"
else 
    echo "(✗) GO: Scan exited with code $SUMMARY_GO"
fi   
if [ $SUMMARY_JAVA -eq 0 ]; then
    echo "(✔) JAVA"
else 
    echo "(✗) JAVA: Scan exited with code $SUMMARY_JAVA"
fi
if [ $SUMMARY_PYTHON -eq 0 ]; then
    echo "(✔) PYTHON"
else 
    echo "(✗) PYTHON: Scan exited with code $SUMMARY_PYTHON"
fi
if [ $SUMMARY_JS -eq 0 ]; then
    echo "(✔) JS"
else 
    echo "(✗) JS: Scan exited with code $SUMMARY_JS"
fi
