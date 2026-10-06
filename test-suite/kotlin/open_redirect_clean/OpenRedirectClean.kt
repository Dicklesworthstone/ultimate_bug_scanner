package security

import java.net.URI

class ApplicationCall(val request: Request) {
    fun respondRedirect(location: String) {}
}

class Request(
    val queryParameters: Map<String, String> = emptyMap(),
    val headers: Map<String, String> = emptyMap()
)

class CleanKotlinRedirects {
    private val allowedHosts = setOf("app.example.com")

    private fun safeRedirectTarget(raw: String): String {
        val uri = URI.create(raw)
        if (uri.isAbsolute) {
            require(uri.scheme == "https" && uri.host in allowedHosts) { "blocked redirect" }
            return uri.toString()
        }
        require(uri.rawAuthority == null && !uri.toString().startsWith("//") && uri.path.startsWith("/") && !uri.path.startsWith("//")) { "blocked redirect" }
        return uri.toString()
    }

    fun redirectQuery(call: ApplicationCall) {
        val target = safeRedirectTarget(call.request.queryParameters["next"] ?: "/")
        call.respondRedirect(target)
    }

    fun redirectHeader(call: ApplicationCall): String {
        val target = safeRedirectTarget(call.request.headers["X-Return-To"] ?: "/")
        return "redirect:$target"
    }
}
