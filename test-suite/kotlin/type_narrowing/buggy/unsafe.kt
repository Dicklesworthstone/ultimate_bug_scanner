data class UserProfile(val email: String?)

class FakeJob {
    val isActive: Boolean = true
    fun cancel() {}
}

fun coroutineJobGuard(job: FakeJob?) {
    if (job?.isActive == true) {
        println("job still running")
    }
    job!!.cancel()
}

fun sendWelcome(profile: UserProfile?) {
    if (profile == null) {
        println("missing profile")
    }

    println("Sending welcome to ${profile!!.email!!.lowercase()}")
}

fun logToken(token: String?) {
    if (token == null) {
        println("no token provided")
    }

    println("token length = ${token!!.length}")
}

fun maybeAvatar(url: String?) {
    if (url == null) {
        println("avatar missing")
    }

    println("avatar host = ${url!!.substringBefore('.')}")
}

fun smartCast(adminCandidate: Any?) {
    val admin = adminCandidate as? MutableMap<String, String>
    println("admin level ${admin!!.getValue("level")}")
}

fun elvisForce(profile: UserProfile?) {
    val alias = profile?.email ?: run { println("no alias yet"); null }
    println("alias length ${alias!!.length}")
}
