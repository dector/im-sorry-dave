package space.dector.gatekeeper.pages

import kotlinx.html.h2
import kotlinx.html.style


internal fun buildInfoPage(
    text: String,
    type: InfoType,
) = webPage(
    title = "Access Denied"
) {
    h2 {
        style = buildString {
            append("text-align: center;")
            append("color: ${type.color}")
        }
        +text
    }
}

enum class InfoType(val color: String) {
    Success("#17b537"), Error("#b57017"),
}
