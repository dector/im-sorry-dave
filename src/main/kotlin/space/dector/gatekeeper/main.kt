package space.dector.gatekeeper

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import org.hjson.JsonValue
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
import org.tinylog.kotlin.Logger
import space.dector.gatekeeper.pages.InfoType
import space.dector.gatekeeper.pages.buildInfoPage
import space.dector.gatekeeper.pages.buildLoginPage
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.thread
import kotlin.concurrent.write
import kotlin.io.path.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createFile
import kotlin.io.path.exists
import kotlin.io.path.extension
import kotlin.io.path.inputStream
import kotlin.io.path.isDirectory
import kotlin.io.path.moveTo
import kotlin.io.path.name
import kotlin.io.path.notExists
import kotlin.io.path.readText
import kotlin.io.path.reader
import kotlin.io.path.writeText


fun main() {
    val config = loadServerConfigurationOrFail()

    val accessManager = AccessManager(
        jwtSecret = config.jwtSecret,
        usersRepo = UsersRepo(config.usersDataFolder),
    )

    val loginManager = LoginManager(
        emailService = EmailService(),
        accept = config.accept,
        loginRepo = LoginRepo(config.loginDataFolder),
    )

    val handler = { request: Request ->
        val interceptionResult = interceptRequest(request, accessManager)

        when (interceptionResult) {
            InterceptionResult.NotAuthorized -> {
                Response(Status.TEMPORARY_REDIRECT)
                    .header("Location", "/auth/login")
            }
            InterceptionResult.Ok.ForContent -> {
                respondWithFileContent(request.uri, config.servingFolder)
            }
            is InterceptionResult.Ok.ForService -> {
                when (interceptionResult.page) {
                    ServicePage.Login ->
                        respondWithLoginPage(request, accessManager, loginManager)
                }
            }
        }
    }

    val server = { request: Request ->
        runCatching { handler(request) }
            .onFailure { err ->
                Logger.error(err) { "Server error" }
            }
            .getOrNull()
            ?: Response(Status.INTERNAL_SERVER_ERROR)
                .body("Internal server error :(")
    }.asServer(Netty(port = config.port)).start()

    println("Server started at http://localhost:${config.port}")

    server.addShutdownHook()
    server.block()
}

internal fun loadServerConfigurationOrFail(): ServerConfig {
    val configFile = System.getenv("GATEKEEPER_CONFIG_FILE")
        ?.let(::Path)
        ?: error("GATEKEEPER_CONFIG_FILE not specified.")

    if (Files.notExists(configFile))
        error("Config file '$configFile' doesn't exist.")

    val json = JsonValue
        .readHjson(configFile.reader())
        .asObject()

    val config = ServerConfig(
        port = json["port"]?.asInt() ?: 9090,
        host = json["host"]?.asString() ?: error("Server host not specified"),
        servingFolder = (json["servingFolder"]?.asString() ?: "public").let(::Path),
        dataFolder = (json["dataFolder"]?.asString() ?: "data").let(::Path),
        jwtSecret = json["jwtSecret"]?.asString() ?: error("JWT secret not specified"),
        accept = json["accept"]?.asObject()?.let { obj ->
            AcceptConfig(
                hosts = obj["hosts"]?.asArray()?.map { it.asString() } ?: emptyList(),
                emails = obj["emails"]?.asArray()?.map { it.asString() } ?: emptyList(),
            )
        } ?: AcceptConfig(),
    )

    if (config.dataFolder.notExists())
        config.dataFolder.createDirectories()

    return config
}

data class ServerConfig(
    val port: Int,
    val host: String,
    val servingFolder: Path,
    val dataFolder: Path,
    val jwtSecret: String,
    val accept: AcceptConfig,
)

data class AcceptConfig(
    val hosts: List<String> = emptyList(),
    val emails: List<String> = emptyList(),
)

val ServerConfig.usersDataFolder: Path get() = dataFolder.resolve("granted")
val ServerConfig.loginDataFolder: Path get() = dataFolder.resolve("requested")

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

    if (!Files.exists(file)) {
        Logger.warn { "Uri '$uri' not found (expected file: '$file')." }
        return Response(Status.NOT_FOUND)
            .body("'$uri' not found on this server")
    }

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
    private val usersRepo: UsersRepo,
) {
    private val jwtTools = JwtTools(jwtSecret)

    fun verify(token: String): Boolean {
        val userEmail = jwtTools.parseUserEmail(token)
            ?: return false

        return usersRepo.isAccessGranted(userEmail)
    }

    fun createTokenFor(email: String): String? {
        usersRepo.grantAccessTo(email)
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
    // TODO rewrite this part. It's difficult to understand
    val tokenToSet = code
        ?.let(loginManager::getEmailForCode)
        ?.also { loginManager.markCodeAsUsed(code) }
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
    private val loginRepo: LoginRepo,
    private val accept: AcceptConfig,
) {

    // See OWASP: https://owasp.org/www-community/OWASP_Validation_Regex_Repository
    private val emailRegex by lazy {
        "^([a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+))*@((?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7})$"
            .toRegex()
    }

    fun createLoginFor(email: String): CodeRequestResult {
        val match = emailRegex.find(email)
            ?: return CodeRequestResult.InvalidEmail

        val (user, host) = match.destructured

        val isEmailAcceptable =
            (host in accept.hosts) || (email in accept.emails)
        if (isEmailAcceptable) {
            val code = createCodeFor(email)
            val loginUrl = buildLoginUrl(code)

            emailService.sendLoginInvitationFor(email, loginUrl)

            return CodeRequestResult.Sent
        } else return CodeRequestResult.DeniedEmail
    }

    fun getEmailForCode(code: String?): String? {
        code ?: return null

        return loginRepo.getEmailForCode(code)
    }

    fun markCodeAsUsed(code: String) {
        loginRepo.markCodeAsUsed(code)
    }

    private fun createCodeFor(email: String): String {
        return UUID.randomUUID().toString()
            .also { code -> loginRepo.saveCodeFor(email, code) }
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

class UsersRepo(
    private val dataFolder: Path,
) {

    init {
        dataFolder.createDirectories()
    }

    private val cacheLock = ReentrantReadWriteLock()
    private val cache = mutableListOf<String>()

    init {
        reloadCache()
    }

    fun isAccessGranted(email: String): Boolean {
        return cacheLock.read {
            email in cache
        }
    }

    fun grantAccessTo(email: String) {
        dataFolder.resolve(email).createFile()
        reloadCache()
    }

    private fun reloadCache() {
        cacheLock.write {
            cache.clear()

            Files.list(dataFolder)
                .forEach { cache.add(it.name) }
        }
    }
}

class LoginRepo(
    private val dataFolder: Path,
) {

    init {
        dataFolder.createDirectories()
    }

    fun getEmailForCode(code: String): String? {
        return dataFolder.resolve(code)
            .takeIf { it.exists() }
            ?.readText()
    }

    fun saveCodeFor(email: String, code: String) {
        codeFile(code).writeText(email)
    }

    fun markCodeAsUsed(code: String) {
        val originalFile = codeFile(code)
        if (originalFile.exists()) {
            val newFile = originalFile.resolveSibling("${originalFile.name}.used")
            originalFile.moveTo(newFile)
        }
    }

    private fun codeFile(code: String): Path =
        dataFolder.resolve(code)
}
