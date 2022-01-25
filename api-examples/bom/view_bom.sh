#!/bin/sh

usage() {
    echo "Usage:"
    echo "$0 <app name> <scan ID>"
    exit 0;
}

if [ -z "${SHIFTLEFT_ORG_ID}" ]; then echo "SHIFTLEFT_ORG_ID is unset"; exit 1; fi
if [ -z "${SHIFTLEFT_ACCESS_TOKEN}" ]; then echo "SHIFTLEFT_ACCESS_TOKEN is unset"; exit 1; fi

if [ -z "$1" ]; then usage; fi # missing app name
if [ -z "$2" ]; then usage; fi # missing scan ID

curl -H "Authorization: Bearer $SHIFTLEFT_ACCESS_TOKEN" \
  "https://www.shiftleft.io/api/v4/private/orgs/$SHIFTLEFT_ORG_ID/apps/$1/scans/$2/bom"
