package space.dector.project

import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status.Companion.OK
import org.http4k.server.Http4kServer
import org.http4k.server.Netty
import org.http4k.server.asServer
import kotlin.concurrent.thread


fun main() {
    val port = System.getProperty("GATEKEEPER_PORT")
        ?.toIntOrNull()
        ?: 9090

    val config = Netty(port = port)
    val server = { request: Request ->
        Response(OK).body(request.uri.toString())
    }.asServer(config).start()

    println("Server started at http://localhost:$port")

    server.addShutdownHook()
    server.block()
}

private fun Http4kServer.addShutdownHook() {
    val server = this

    Runtime.getRuntime().addShutdownHook(thread(start = false) {
        println("Stopping server...")
        server.stop()
        println("Bye-bye.")
    })
}
