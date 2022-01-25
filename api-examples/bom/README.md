# View scan BOM

`view_bom.sh` fetches the BOM from a scan (if one exists).

### Usage

Set `SHIFTLEFT_ORG_ID` and `SHIFTLEFT_ACCESS_TOKEN`.

```
./view_bom.sh <app name> <scan ID>
```

The output is printed as JSON.

### Example

```
./view_bom.sh shiftleft-js-demo 236
{
  "ok": true,
  "response": {
    "XMLName": {
      "Space": "http://cyclonedx.org/schema/bom/1.2",
      "Local": "bom"
    },
    "Xmlns": "http://cyclonedx.org/schema/bom/1.2",
    "SerialNumber": "urn:uuid:9585e958-7d41-43f7-93fb-3facbf1162eb",
    "Version": "1",
    "ExternalReferences": {
      "Reference": [
        {
          "Type": "other",
          "URL": "/Users/preetam/src/shiftleft-js-demo",
          "Comment": "Base path"
        },
[rest omitted]
```
