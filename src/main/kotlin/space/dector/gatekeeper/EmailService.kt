package space.dector.gatekeeper

import com.sendgrid.Content
import com.sendgrid.Email
import com.sendgrid.Mail
import com.sendgrid.Method
import com.sendgrid.Request
import com.sendgrid.SendGrid
import org.tinylog.kotlin.Logger

class EmailService(
    private val senderEmail: String,
    private val serviceName: String,
    sendGridApiKey: String?,
) {

    private val sendGrid = sendGridApiKey?.let(::SendGrid)

    fun sendLoginInvitationFor(email: String, loginUrl: String) {
        sendGrid ?: run {
            Logger.warn { "SendGrid API Key not specified. Here is login link for $email: $loginUrl" }
            return
        }
        sendGrid.api(Request().apply {
            method = Method.POST
            endpoint = "mail/send"
            body = Mail(
                Email(senderEmail, serviceName),
                "Login to $serviceName",
                Email(email),
                Content(
                    "text/plain",
                    "Login to $serviceName with this link: $loginUrl",
                )
            ).build()
        })

    }
}
