package space.dector.project

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status
import org.http4k.core.Uri
import org.http4k.core.cookie.Cookie
import org.http4k.core.cookie.SameSite
import org.http4k.core.cookie.cookie
import org.http4k.server.Http4kServer
import org.http4k.server.Netty
import org.http4k.server.asServer
import java.nio.file.Files
import java.nio.file.Path
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
                        respondWithLoginPage(request, accessManager)
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
        val pathToFile = uri.toString().trimStart('/')

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

    private val allowedUsers = listOf<String>(
        "dan@example.com",
    )

    fun verify(token: String): Boolean {
        val userEmail = jwtTools.parseUserEmail(token)
            ?: return false

        return userEmail in allowedUsers
    }

    fun createTokenFor(email: String): String? {
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

private fun respondWithLoginPage(request: Request, accessManager: AccessManager): Response {
    val tokenToSet = request.query("code")
        ?.let { code -> getEmailForLoginCodeOrNull(code) }
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
            .body("TODO: login")
    }
}

// TODO use storage
private fun getEmailForLoginCodeOrNull(code: String): String? {
    // TODO fetch values from storage
    val data = mapOf(
        "1234" to "dan@example.com",
    )

    return data[code]
}
