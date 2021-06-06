package space.dector.gatekeeper

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import org.http4k.core.Method
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status
import org.http4k.core.Uri
import org.http4k.core.body.form
import org.http4k.core.cookie.Cookie
import org.http4k.core.cookie.cookie
import org.http4k.server.Http4kServer
import org.http4k.server.Netty
import org.http4k.server.asServer
import space.dector.gatekeeper.pages.InfoType
import space.dector.gatekeeper.pages.buildInfoPage
import space.dector.gatekeeper.pages.buildLoginPage
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import kotlin.concurrent.thread
import kotlin.io.path.Path
import kotlin.io.path.extension
import kotlin.io.path.inputStream
import kotlin.io.path.isDirectory


fun main() {
    val port = System.getenv("GATEKEEPER_PORT")
        ?.toIntOrNull()
        ?: 9090
    val servingFolder = (System.getenv("GATEKEEPER_FOLDER")
        ?: "public")
        .let(::Path)
    val jwtSecret = System.getenv("GATEKEEPER_JWT_SECRET")
        ?: error("JWT secret is not defined: GATEKEEPER_JWT_SECRET not found.")

    val accessManager = AccessManager(
        jwtSecret = jwtSecret,
    )

    val loginManager = LoginManager(
        emailService = EmailService(),
        // TODO remove
        allowedHosts = listOf("example.com"),
    )

    val config = Netty(port = port)
    val server = { request: Request ->
        val interceptionResult = interceptRequest(request, accessManager)

        when (interceptionResult) {
            InterceptionResult.NotAuthorized -> {
                Response(Status.TEMPORARY_REDIRECT)
                    .header("Location", "/auth/login")
            }
            InterceptionResult.Ok.ForContent -> {
                respondWithFileContent(request.uri, servingFolder)
            }
            is InterceptionResult.Ok.ForService -> {
                when (interceptionResult.page) {
                    ServicePage.Login ->
                        respondWithLoginPage(request, accessManager, loginManager)
                }
            }
        }
    }.asServer(config).start()

    println("Server started at http://localhost:$port")

    server.addShutdownHook()
    server.block()
}

private fun interceptRequest(
    request: Request,
    accessManager: AccessManager,
): InterceptionResult {
    val servicePage = ServicePage.forPath(request.uri.path)
    if (servicePage != null)
        return InterceptionResult.Ok.ForService(servicePage)

    val token = request.cookie("SERVICE_TOKEN")
        ?.value
        ?: return InterceptionResult.NotAuthorized

    return if (accessManager.verify(token))
        InterceptionResult.Ok.ForContent
    else InterceptionResult.NotAuthorized
}

private fun respondWithFileContent(uri: Uri, servingFolder: Path): Response {
    val file = run {
        val pathToFile = uri.toSecureRelativePath()
        servingFolder.resolve(pathToFile)
            .let { if (it.isDirectory()) it.resolve("index.html") else it }
    }

    if (!Files.exists(file))
        return Response(Status.NOT_FOUND)
            .body("'$uri' not found on this server")

    return Response(Status.OK)
        .header("Content-Type", file.contentTypeOrDefault())
        .body(file.inputStream())
}

private sealed class InterceptionResult {
    object NotAuthorized : InterceptionResult()
    sealed class Ok : InterceptionResult() {
        object ForContent : Ok()
        data class ForService(val page: ServicePage) : Ok()
    }
}

private enum class ServicePage(val path: String) {
    Login("/auth/login"),
    ;

    companion object {
        private val allPages = values()

        fun forPath(path: String): ServicePage? = allPages.firstOrNull { it.path == path }
    }
}

private fun Http4kServer.addShutdownHook() {
    val server = this

    Runtime.getRuntime().addShutdownHook(thread(start = false) {
        println("Stopping server...")
        server.stop()
        println("Bye-bye.")
    })
}

private val knownContentTypes = mutableMapOf<String, String>()
private fun Path.contentTypeOrDefault(): String {
    return knownContentTypes.getOrPut(extension) {
        runCatching { Files.probeContentType(this) }
            .getOrNull()
            ?: "text/plain"
    }
}

private class AccessManager(
    jwtSecret: String,
) {

    private val jwtTools = JwtTools(jwtSecret)

    private val allowedUsers = mutableSetOf<String>()

    fun verify(token: String): Boolean {
        val userEmail = jwtTools.parseUserEmail(token)
            ?: return false

        return userEmail in allowedUsers
    }

    fun createTokenFor(email: String): String? {
        allowedUsers += email
        return jwtTools.createToken(email)
    }
}

class JwtTools(
    secret: String,
) {
    private val issuer = "auth0"

    private val algorithm: Algorithm = Algorithm.HMAC256(secret)
    private val verifier = JWT.require(algorithm)
        .withIssuer(issuer)
        .build()

    fun createToken(email: String): String? =
        runCatching {
            JWT.create()
                .withIssuer(issuer)
                .withSubject(email)
                .sign(algorithm)
        }.getOrNull()

    fun parseUserEmail(token: String): String? {
        val jwt = runCatching { verifier.verify(token) }
            .getOrNull()

        return jwt?.subject
    }
}

private fun respondWithLoginPage(
    request: Request,
    accessManager: AccessManager,
    loginManager: LoginManager,
): Response {
    return when (request.method) {
        Method.GET ->
            loginPageGet(
                code = request.query("code"),
                accessManager = accessManager,
                loginManager = loginManager,
            )
        Method.POST ->
            loginPagePost(
                email = request.form("email"),
                loginManager = loginManager,
            )
        else ->
            Response(Status.TEMPORARY_REDIRECT)
                .header("Location", "/")
    }
}

private fun loginPageGet(code: String?, accessManager: AccessManager, loginManager: LoginManager): Response {
    val tokenToSet = code
        ?.let(loginManager::getEmailForCode)
        ?.let { email -> accessManager.createTokenFor(email) }

    return if (tokenToSet != null) {
        Response(Status.TEMPORARY_REDIRECT)
            .header("Location", "/")
            .cookie(
                Cookie(
                    name = "SERVICE_TOKEN",
                    value = tokenToSet,
                    secure = true,
                    httpOnly = true,
                    path = "/",
                )
            )
    } else {
        Response(Status.OK)
            .body(buildLoginPage())
    }
}

private fun loginPagePost(email: String?, loginManager: LoginManager): Response {
    email ?: return Response(Status.TEMPORARY_REDIRECT)
        .header("Location", "/")

    return when (loginManager.createLoginFor(email)) {
        CodeRequestResult.Sent -> {
            Response(Status.OK)
                .body(
                    buildInfoPage(
                        text = "Check your mailbox on $email for login link.",
                        type = InfoType.Success,
                    )
                )
        }
        CodeRequestResult.InvalidEmail -> {
            Response(Status.BAD_REQUEST)
                .body(
                    buildLoginPage(
                        error = "Email is not valid",
                    )
                )
        }
        CodeRequestResult.DeniedEmail -> {
            Response(Status.FORBIDDEN)
                .body(
                    buildInfoPage(
                        text = "Sorry, you can't access content with this email",
                        type = InfoType.Error,
                    )
                )
        }
    }
}

class LoginManager(
    private val emailService: EmailService,
    private val allowedEmails: List<String> = emptyList(),
    private val allowedHosts: List<String> = emptyList(),
) {

    // See OWASP: https://owasp.org/www-community/OWASP_Validation_Regex_Repository
    private val emailRegex by lazy {
        "^([a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+))*@((?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7})$"
            .toRegex()
    }

    // TODO use persistent storage
    private val accessCodesStorage = mutableMapOf<String, String>()

    fun createLoginFor(email: String): CodeRequestResult {
        val match = emailRegex.find(email)
            ?: return CodeRequestResult.InvalidEmail

        val (user, host) = match.destructured

        val isEmailAcceptable =
            (host in allowedHosts) || (email in allowedEmails)
        if (isEmailAcceptable) {
            val code = createCodeFor(email)
            val loginUrl = buildLoginUrl(code)

            emailService.sendLoginInvitationFor(email, loginUrl)

            return CodeRequestResult.Sent
        } else return CodeRequestResult.DeniedEmail
    }

    fun getEmailForCode(code: String?): String? {
        code ?: return null

        return accessCodesStorage
            .entries
            .firstOrNull { (_, storedCode) -> storedCode == code }
            ?.key
    }

    private fun createCodeFor(email: String): String {
        return UUID.randomUUID().toString()
            .also { accessCodesStorage[email] = it }
    }

    private fun buildLoginUrl(code: String): String {
        // TODO
        return "http://localhost:9090/auth/login?code=$code"
    }
}

sealed class CodeRequestResult {
    object Sent : CodeRequestResult()
    object InvalidEmail : CodeRequestResult()
    object DeniedEmail : CodeRequestResult()
}

class EmailService {

    fun sendLoginInvitationFor(email: String, loginUrl: String) {
        // TODO send real email
        println("=== $email ===")
        println("Login with: $loginUrl")
    }
}

private val rootPath = Path("/")
fun Uri.toSecureRelativePath(): Path =
    Path(toString())
        .normalize()
        .let(rootPath::relativize)
