package space.dector.gatekeeper.pages

import kotlinx.html.LinkRel
import kotlinx.html.MAIN
import kotlinx.html.body
import kotlinx.html.head
import kotlinx.html.html
import kotlinx.html.link
import kotlinx.html.main
import kotlinx.html.meta
import kotlinx.html.stream.createHTML
import kotlinx.html.style
import kotlinx.html.title


internal fun webPage(
    title: String,
    content: MAIN.() -> Unit,
): String = createHTML()
    .html {
        attributes["data-theme"] = "dark"

        head {
            meta(charset = "utf-8")
            meta("viewport", "width=device-width, initial-scale=1, shrink-to-fit=no, viewport-fit=cover")

            title { +title }
            link(
                href = "https://unpkg.com/@picocss/pico@latest/css/pico.min.css",
                rel = LinkRel.stylesheet,
            )
        }
        body {
            style = "min-height: 100vh; display: flex; align-items: center;"

            main(
                classes = "container"
            ) {
                content()
            }
        }
    }
