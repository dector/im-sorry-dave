package space.dector.project

import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status
import org.http4k.core.Uri
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
    val port = System.getProperty("GATEKEEPER_PORT")
        ?.toIntOrNull()
        ?: 9090
    val servingFolder = (System.getProperty("GATEKEEPER_FOLDER")
        ?: "public")
        .let(::Path)

    val config = Netty(port = port)
    val server = { request: Request ->
        val interceptionResult = interceptRequest(request)

        when (interceptionResult) {
            InterceptionResult.NotAuthorized -> {
                Response(Status.TEMPORARY_REDIRECT)
                    .header("Location", "/auth/login")
            }
            InterceptionResult.Ok -> {
                respondWithFileContent(request.uri, servingFolder)
            }
        }
    }.asServer(config).start()

    println("Server started at http://localhost:$port")

    server.addShutdownHook()
    server.block()
}

private fun interceptRequest(request: Request): InterceptionResult {
    if (request.uri.toString() == ServicePages.Login)
        return InterceptionResult.Ok

    return InterceptionResult.Ok
    // TODO Validate user JWT
//    return InterceptionResult.NotAuthorized
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
    object Ok : InterceptionResult()
}

private object ServicePages {
    const val Login = "/auth/login"
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
