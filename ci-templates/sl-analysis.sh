#!/usr/bin/env bash
# Invoke maven and specify the target director here
# For javascript, we look for package.json
TARGET_DIR=target
POM_COUNT=$(find . -maxdepth 1 -type f -name "pom.xml" -not -path '*/\.git/*' | wc -l | tr -d " ")
GRADLE_COUNT=$(find . -maxdepth 1 -type f -name "build.gradle" -not -path '*/\.git/*' | wc -l | tr -d " ")
if [ "$POM_COUNT" != "0" ]; then
  mvn compile package -Dmaven.test.skip=true
  BUILT=1
elif [ "$GRADLE_COUNT" != "0" ]; then
  gradle jar
  #./gradlew jar
  TARGET_DIR=build
  BUILT=1
fi
if [ -d "$TARGET_DIR" ]; then
    jar cvf app.jar -C $TARGET_DIR .
    sl analyze --wait --app "$CI_PROJECT_NAME" --version-id "$CI_COMMIT_SHA" --tag branch="$CI_COMMIT_REF_NAME" --java app.jar
elif [ -e "package.json" ]; then
    sl analyze --wait --app "$CI_PROJECT_NAME" --version-id "$CI_COMMIT_SHA" --tag branch="$CI_COMMIT_REF_NAME" --js .
elif [ -d "terraform" ]; then
    sl analyze --wait --app "$CI_PROJECT_NAME" --version-id "$CI_COMMIT_SHA" --tag branch="$CI_COMMIT_REF_NAME" --terraform .    
fi
# Check if this is running in a merge request
if [ -n "$CI_MERGE_REQUEST_IID" ] && [ -n "$MR_TOKEN" ]; then
  echo "Got merge request $CI_MERGE_REQUEST_IID for branch $CI_COMMIT_REF_NAME"

  # Run check-analysis and save report to /tmp/check-analysis.md
  sl check-analysis \
    --app "$CI_PROJECT_NAME" \
    --report \
    --report-file /tmp/check-analysis.md \
    --source "tag.branch=master" \
    --target "tag.branch=$CI_COMMIT_REF_NAME"

  CHECK_ANALYSIS_OUTPUT=$(cat /tmp/check-analysis.md)
  COMMENT_BODY=$(jq -n --arg body "$CHECK_ANALYSIS_OUTPUT" '{body: $body}')

  # Post report as merge request comment
  curl -i -XPOST "https://gitlab.com/api/v4/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes" \
    -H "PRIVATE-TOKEN: $MR_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$COMMENT_BODY"
fi

