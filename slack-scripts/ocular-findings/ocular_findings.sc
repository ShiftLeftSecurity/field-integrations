/* ocular_findings
   Version: 0.0.1
   Ocular Version: 0.4.9+
   Author: Suchakra Sharma <suchakra@shiftLeft.io>
   Description: Generate default findings from an application and attach as a slack message
 */

import $ivy.`org.latestbit::slack-morphism-client:3.2.0`
import $ivy.`com.softwaremill.sttp.client::async-http-client-backend-cats:2.2.9`
import org.latestbit.slack.morphism.client._
import sttp.client.asynchttpclient.cats.AsyncHttpClientCatsBackend
import org.latestbit.slack.morphism.common.{SlackAccessTokenValue, SlackApiTokenScope, SlackChannelId}
import cats.effect._
import cats.data._
import org.latestbit.slack.morphism.client.reqresp.test.SlackApiTestRequest
import org.latestbit.slack.morphism.client.reqresp.chat.SlackApiChatPostMessageRequest
import org.latestbit.slack.morphism.client.reqresp.files.SlackApiFilesUploadRequest
import scala.concurrent.duration._

implicit val cs: ContextShift[IO] = IO.contextShift( scala.concurrent.ExecutionContext.global )

implicit val testApiUserToken = 
  SlackApiBotToken(
    SlackAccessTokenValue("xoxb-70...") // Replace token with "Bot user OAuth Token" under "OAuth & Permissions"
  )

val id = SlackChannelId("#ocular") // Replace with your channel. Make sure app is added to channel via "Integrations"

implicit val channelOrder = new cats.kernel.Order[SlackChannelId]{ 
    def compare(x: SlackChannelId, y: SlackChannelId) = x.value.compareTo(y.value)
}

@main def execute() : Boolean = {
  // Generate CPG and default findings
  importCode("/home/suchakra/Projects/explnode") // Replace with your project
  run.securityprofile
  cpg.finding.p |> "findings.txt"

  // Prepare IO for slack
  val io = for {
    backend <- AsyncHttpClientCatsBackend[IO]() // Creating an STTP backend
    client = SlackApiClient.build[IO]( backend ).create() // Create a Slack API client

    // First message
    result1 <- client.chat.postMessage(
      SlackApiChatPostMessageRequest(
        channel = id,
        text = "📢 Default Findings for " + workspace.getActiveProject.map(_.projectFile.name).getOrElse("<APP>")
      )
    )

    // Upload findings.txt file
    result2 <- client.files.upload(
      SlackApiFilesUploadRequest(
        channels = Option(NonEmptySet.of(id)),
        filename = "findings.txt"
      ), new java.io.FileInputStream("findings.txt")
    )
  } yield result2

  // execute IO
  io.unsafeRunAsync(_ => ())

  return true
}
