# CLI-Analyze-Demo
The following script will download Shiftleft docker image and analyze our demo applications.  The script can be altered to analyze other applications.

Requirements:
* Docker must be installed
* Authenticated to Shiftleft. export the SHIFTLEFT_ACCESS_TOKEN by running the following command:

``bash
export SHIFTLEFT_ACCESS_TOKEN=YOUR_ACCESS_TOKEN_FOR_SHIFTLEFT
```
* Update the script with your working directory by setting `DOCKER_WORK_DIR` variable.  This is the path where the github repos will be downloaded to.
* **Must** have git installed.
