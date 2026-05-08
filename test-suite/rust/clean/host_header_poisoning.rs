struct HeaderMap;
struct HeaderValue;
struct Request;

const PUBLIC_ORIGIN: &str = "https://app.example.com";
const ALLOWED_HOSTS: &[&str] = &["app.example.com", "accounts.example.com"];

impl Request {
    fn host(&self) -> Option<&str> {
        Some("app.example.com")
    }

    fn headers(&self) -> HeaderMap {
        HeaderMap
    }
}

impl HeaderMap {
    fn get(&self, _name: &str) -> Option<HeaderValue> {
        Some(HeaderValue)
    }
}

impl HeaderValue {
    fn to_str(&self) -> Result<&str, ()> {
        Ok("app.example.com")
    }
}

fn trusted_origin_from_host(raw_host: &str) -> Result<String, &'static str> {
    let host = raw_host.trim();
    if !ALLOWED_HOSTS.contains(&host) {
        return Err("untrusted host");
    }
    Ok(format!("https://{host}"))
}

fn password_reset_url_from_config(_req: Request, token: &str) -> String {
    format!("{PUBLIC_ORIGIN}/reset?token={token}")
}

fn forwarded_verification_url_allowed(req: Request, token: &str) -> Result<String, &'static str> {
    let raw_host = req
        .headers()
        .get("x-forwarded-host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("app.example.com");
    let origin = trusted_origin_from_host(raw_host)?;
    Ok(format!("{origin}/verify?token={token}"))
}

fn inline_allowlist_before_build(req: Request) -> Result<String, &'static str> {
    let host = req.host().unwrap_or("");
    if !ALLOWED_HOSTS.contains(&host) {
        return Err("untrusted host");
    }
    Ok(format!("https://{host}/dashboard"))
}

fn audit_request_host(req: Request) -> bool {
    req.host().is_some()
}

fn literal_host_after_audit(path: &str) -> String {
    let host = "app.example.com";
    format!("https://{host}{path}")
}
