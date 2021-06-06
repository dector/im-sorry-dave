package space.dector.gatekeeper.pages

import kotlinx.html.ButtonType
import kotlinx.html.FormMethod
import kotlinx.html.InputType
import kotlinx.html.button
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.input
import kotlinx.html.label
import kotlinx.html.style


internal fun buildLoginPage(
    error: String? = null,
) = webPage(
    title = "Login"
) {
    form(
        action = "/auth/login",
        method = FormMethod.post,
    ) {
        label {
            input(
                type = InputType.email,
                name = "email",
            ) {
                if (error != null) attributes["aria-invalid"] = "true"

                placeholder = "E-mail"
                required = true
            }
            if (error != null) {
                div {
                    style = "color: red;"
                    +error
                }
            }
        }

        button(
            classes = "secondary",
            type = ButtonType.submit,
        ) {
            +"Request access"
        }
    }
}
