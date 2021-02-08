# Policy Samples

Collection of policy samples for use with ShiftLeft NG SAST. The default folder contains numerous policies that can be used as a base for customization.

## Common Steps

The user should be an administrator on the ShiftLeft platform. Contributors can author, validate and commit the file to the git repository for administrator to review and push.

To create a sample policy file called my-rules.policy

```
sl policy create default my-rules.policy
```

Edit this file in your favourite editor. To validate this file

```
sl policy validate my-rules.policy
```

Policy files have to be pushed to ShiftLeft. Policy label should not have special characters including hyphen. Here a single word "javarules" is chosen as the label.

```
sl policy push javarules my-rules.policy
```

Post a successful upload the full path to the label will be printed which is of the form <org id> / label : latest. Subsequent usage of policy in sl analyze command should use this full form.

uploaded policy: 2c089ac1-3378-44d5-94da-9507e84351c3/javarules:latest

```
sl analyze --wait --policy 2c089ac1-3378-44d5-94da-9507e84351c3/javarules:latest --app hsl --java --cpg target/hello-shiftleft-0.0.1.jar
```

### Assigning Default Policies

Default for an app

```
sl policy assignment set --project <name> <org id> / label : latest
```

Default for the org

```
sl policy assignment set <org id> / label : latest
```

## References

- [Custom Policies](https://docs.shiftleft.io/ngsast/policies/custom-policies)
- [Policy Language Reference](https://docs.shiftleft.io/core-concepts/policy-language)
