#! /bin/bash
# *** ENV Variables ***

# Set absolute path to working directory.
# "/home/user/projects/projectfolder" or "/home/user/projects/projectfolder/project.jar"
DOCKER_WORK_DIR="/Users/yusefsaraby/projects/testing" # <-- Update per comment above
DOCKER_IMAGE_NAME=shiftleft/core:latest
# Variable Cleanup
## Remove trailing slash(es) if present
DOCKER_WORK_DIR=$(echo "$DOCKER_WORK_DIR" | sed 's:/*$::')

# Check heck if Docker is installed
if ! [ -x "$(command -v docker)" ]; then
    echo "Install docker"
    exit 126
    # command
fi
# Get the lastest docker image
docker pull $DOCKER_IMAGE_NAME

# $1: language (python, go, js, java)
# $2: absolute path to code or binaries
shiftleft_analyze_code() {
    echo "Parameters passed: $1 > $2"
    docker run --rm -e SHIFTLEFT_ACCESS_TOKEN -v "$2":/myvol -it $DOCKER_IMAGE_NAME sl analyze --wait --app shiftleft-js-demo --"$1" /myvol
}

# $1: absolute path to code or binaries
run_demo_go() {
    echo "Run Go Demo: Parameters passed: $1"
    shiftleft_analyze_code "go" "$1"
    docker run --rm -e SHIFTLEFT_ACCESS_TOKEN -v "$1":/myvol -it $DOCKER_IMAGE_NAME /bin/bash -c "cd /myvol; go build; sl analyze --wait --app shiftleft-go-demo --go /myvol"
}

# $1: absolute path to code or binaries
run_demo_java() {
    echo "Run Java Demo: Parameters passed: $1"
    shiftleft_analyze_code "java" "$1"
    docker run --rm -e SHIFTLEFT_ACCESS_TOKEN -v "$1":/myvol -it $DOCKER_IMAGE_NAME /bin/bash -c "cd /myvol; mvn clean package; sl analyze --wait --app shiftleft-java-demo --java /myvol/target/hello-shiftleft-0.0.1.jar"
}

# $1: absolute path to code or binaries
run_demo_python() {
    echo "Run Python Demo: Parameters passed: $1"
    echo "Python path is: " pwd
    shiftleft_analyze_code "python" "$1"
    docker run --rm -e SHIFTLEFT_ACCESS_TOKEN -v "$1":/myvol -it $DOCKER_IMAGE_NAME /bin/bash -c "cd /myvol; pip install -r requirements.txt; sl analyze --wait --app shiftleft-python-demo --python /myvol"
}

# SL to analyze demo applications
echo "************** GO *************"
git clone https://github.com/ShiftLeftSecurity/shiftleft-go-demo.git || true
run_demo_go "$DOCKER_WORK_DIR/shiftleft-go-demo" || true

echo "************** JAVA *************"
git clone https://github.com/ShiftLeftSecurity/shiftleft-java-demo.git || true
run_demo_java "$DOCKER_WORK_DIR/shiftleft-java-demo" || true

echo "************** PYTHON *************"
git clone https://github.com/ShiftLeftSecurity/shiftleft-python-demo.git || true
run_demo_python "$DOCKER_WORK_DIR/shiftleft-python-demo" || true

echo "************** JS *************"
git clone https://github.com/ShiftLeftSecurity/shiftleft-js-demo.git || true
shiftleft_analyze_code "js" "$DOCKER_WORK_DIR/shiftleft-js-demo" || true

echo "DONE"