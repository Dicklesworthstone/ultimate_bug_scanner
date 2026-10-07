import Foundation

enum RedirectError: Error {
    case blocked
}

struct Content {
    func get<T>(_ type: T.Type, at key: String) throws -> String { key }
}

struct Headers {
    subscript(name: String) -> String? { name }
    func first(name: String) -> String? { name }
}

struct Request {
    let query: [String: String]
    let parameters: [String: String]
    let headers: Headers
    let content: Content

    func redirect(to target: String) -> Response {
        Response(status: .found, headers: ["Location": target])
    }
}

enum Status {
    case found
}

struct Response {
    var status: Status
    var headers: [String: String]

    static func redirect(to target: String) -> Response {
        Response(status: .found, headers: ["Location": target])
    }
}

let allowedRedirectHosts = Set(["app.example.com", "accounts.example.com"])

func safeRedirectURL(_ raw: String) throws -> String {
    if raw.hasPrefix("/") && !raw.hasPrefix("//") && !raw.contains("\\") &&
       !raw.contains("\t") && !raw.contains("\r") && !raw.contains("\n") {
        return raw
    }

    guard let url = URL(string: raw),
          url.scheme == "https",
          let host = url.host,
          allowedRedirectHosts.contains(host) else {
        throw RedirectError.blocked
    }
    return url.absoluteString
}

func helperValidatedQuery(req: Request) throws -> Response {
    let rawTarget = req.query["returnUrl"] ?? "/"
    let target = try safeRedirectURL(rawTarget)
    return req.redirect(to: target)
}

func helperValidatedHeader(request: Request) throws -> Response {
    let rawTarget = request.headers.first(name: "X-Redirect") ?? "/"
    let target = try safeRedirectURL(rawTarget)
    return Response.redirect(to: target)
}

func helperValidatedContent(req: Request) throws -> Response {
    let rawTarget = try req.content.get(String.self, at: "redirectUrl")
    let target = try safeRedirectURL(rawTarget)
    return Response.redirect(to: target)
}

func inlineLocalGuard(req: Request) throws -> Response {
    let target = req.parameters["next"] ?? "/"
    guard target.hasPrefix("/") && !target.hasPrefix("//") && !target.contains("\\") &&
          !target.contains("\t") && !target.contains("\r") && !target.contains("\n") else {
        throw RedirectError.blocked
    }
    return req.redirect(to: target)
}

func inlineHostAllowlist(req: Request) throws -> Response {
    let target = req.query["continue"] ?? "/"
    guard let url = URL(string: target),
          url.scheme == "https",
          let host = url.host,
          allowedRedirectHosts.contains(host) else {
        throw RedirectError.blocked
    }
    return Response.redirect(to: url.absoluteString)
}

func validatedLocationHeader(req: Request) throws -> Response {
    let rawTarget = req.query["location"] ?? "/"
    let target = try safeRedirectURL(rawTarget)
    var response = Response(status: .found, headers: [:])
    response.headers["Location"] = target
    return response
}
