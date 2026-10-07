import Foundation

struct Content {
    func get<T>(_ type: T.Type, at key: String) throws -> String {
        return key
    }
}

struct CookieJar {
    subscript(name: String) -> String? { name }
}

struct Headers {
    subscript(name: String) -> String? {
        get { name }
        set {}
    }

    func first(name: String) -> String? {
        return name
    }

    mutating func add(name: String, value: String) {}
    mutating func replaceOrAdd(name: String, value: String) {}
}

struct Request {
    let query: [String: String]
    let parameters: [String: String]
    let headers: Headers
    let cookies: CookieJar
    let url: URL
    let content: Content
}

enum Status {
    case ok
}

struct Response {
    var status: Status
    var headers: [String: String]
}

struct HTTPHeaders {
    init(_ pairs: [(String, String)]) {}
}

enum HeaderError: Error {
    case invalid
}

enum RedirectError: Error {
    case blocked
}

let allowedRedirectHosts = Set(["app.example.com", "accounts.example.com"])

func safeHeaderValue(_ raw: String) -> String {
    return raw
        .replacingOccurrences(of: "\r", with: "")
        .replacingOccurrences(of: "\n", with: "")
}

func encodedFilename(_ raw: String) -> String {
    return raw.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? "download"
}

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

func displayName(req: Request) -> Response {
    let name = safeHeaderValue(req.query["displayName"] ?? "guest")
    var response = Response(status: .ok, headers: [:])
    response.headers["X-Display-Name"] = name
    return response
}

func download(req: Request) -> Response {
    let filename = encodedFilename(req.parameters["filename"] ?? "report.csv")
    return Response(
        status: .ok,
        headers: ["Content-Disposition": "attachment; filename=\(filename)"]
    )
}

func traceHeader(request: Request) -> Response {
    let trace = (request.headers.first(name: "X-Trace-ID") ?? "")
        .replacingOccurrences(of: "\r", with: "")
        .replacingOccurrences(of: "\n", with: "")
    var headers = Headers()
    headers.add(name: "X-Upstream-Trace", value: trace)
    return Response(status: .ok, headers: [:])
}

func contentHeader(req: Request) throws -> Response {
    let tenant = try req.content.get(String.self, at: "tenantHeader")
    guard !tenant.contains("\r"), !tenant.contains("\n") else {
        throw HeaderError.invalid
    }
    var response = Response(status: .ok, headers: [:])
    response.headers["X-Tenant"] = tenant
    return response
}

func cookiesHeader(req: Request) -> HTTPHeaders {
    let exportName = safeHeaderValue(req.cookies["exportName"] ?? "report")
    return HTTPHeaders([("X-Export-Name", exportName)])
}

func locationOnlyHeader(req: Request) throws -> Response {
    let rawTarget = req.query["location"] ?? "/"
    let target = try safeRedirectURL(rawTarget)
    return Response(status: .ok, headers: ["Location": target])
}
