## Ocular Findings Slack Notifier

### Setup

1. Create an App called Ocular Findings using `manifest.yml`. Use the `sl_icon.png` as the App logo.
2. Install the app to workspace using https://api.slack.com/apps, selecting "Ocular Findings" and clikcing Install to Workspace. Admin permission may be required. 
3. Upon installing, use the "Bot User OAuth Token" under "OAuth and Permissions" (starts with `xoxb-70...`) as the `SlackApiBotToken` in the script
4. Replace the `SlackChannelId` called `id` in script with the channel in which messages are sent. Ensure App is installed **for that channel**. You can click channel name > Integrations > Add apps to add the app to the channel
5. Once the app is setup, you can now use the script interactively or externally as part of automation  

### Interactive Usage

```scala
ocular> import $file.ocular_findings
ocular> ocular_findings.execute()
```

### Automated Usage

```bash
$ sl ocular -- --script ocular_findings.sc
```

### External Dependencies
These are fetched as part of script directly from ammonite

 - `org.latestbit::slack-morphism-client:3.2.0` (https://slack.abdolence.dev/docs/index) **Note:** docs are not always updated. 
 - `com.softwaremill.sttp.client::async-http-client-backend-cats:2.2.9`
