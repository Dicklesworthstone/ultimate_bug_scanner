struct HeaderMap;
struct HeaderValue;
struct Request;
struct Uri;
struct UriBuilder;

impl Request {
    fn host(&self) -> Option<&str> {
        Some("attacker.example")
    }

    fn headers(&self) -> HeaderMap {
        HeaderMap
    }

    fn uri(&self) -> Uri {
        Uri
    }
}

impl HeaderMap {
    fn get(&self, _name: &str) -> Option<HeaderValue> {
        Some(HeaderValue)
    }
}

impl HeaderValue {
    fn to_str(&self) -> Result<&str, ()> {
        Ok("attacker.example")
    }
}

impl Uri {
    fn builder() -> UriBuilder {
        UriBuilder
    }

    fn host(&self) -> Option<&str> {
        Some("attacker.example")
    }
}

impl UriBuilder {
    fn scheme(self, _scheme: &str) -> Self {
        self
    }

    fn authority(self, _authority: &str) -> Self {
        self
    }

    fn path_and_query(self, _path: &str) -> Self {
        self
    }

    fn build(self) -> Result<Uri, ()> {
        Ok(Uri)
    }
}

fn password_reset_url(req: Request, token: &str) -> String {
    let host = req.host().unwrap_or("localhost");
    format!("https://{host}/reset?token={token}")
}

fn forwarded_verification_url(req: Request, token: &str) -> String {
    let host = req
        .headers()
        .get("x-forwarded-host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| req.uri().host().unwrap_or(""));
    format!("https://{host}/verify?token={token}")
}

fn canonical_url_from_header(headers: HeaderMap, path: &str) -> String {
    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost");
    format!("https://{host}{path}")
}

fn email_link_from_host(req: Request, token: &str) -> String {
    let host = req.host().unwrap_or("");
    "https://".to_string() + host + "/email/verify?token=" + token
}

fn reset_url_with_validation_too_late(req: Request, token: &str) -> Result<String, &'static str> {
    let host = req.host().unwrap_or("");
    let reset_link = format!("https://{host}/reset?token={token}");
    if !["app.example.com"].contains(&host) {
        return Err("untrusted host");
    }
    Ok(reset_link)
}

fn authority_builder_from_host(req: Request) -> Uri {
    let host = req.host().unwrap_or("");
    Uri::builder()
        .scheme("https")
        .authority(host)
        .path_and_query("/dashboard")
        .build()
        .unwrap()
}
