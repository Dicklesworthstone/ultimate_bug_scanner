use axum::extract::Query;
use axum::response::Redirect;
use std::collections::HashMap;
use url::Url;

const LOCATION: &str = "Location";

struct HeaderMap;
struct HeaderValue;
struct Request;
struct Response;
struct ResponseBuilder;

impl HeaderMap {
    fn get(&self, _name: &str) -> Option<HeaderValue> {
        Some(HeaderValue)
    }
}

impl HeaderValue {
    fn to_str(&self) -> Result<&str, ()> {
        Ok("/dashboard")
    }
}

impl Request {
    fn headers(&self) -> HeaderMap {
        HeaderMap
    }
}

impl Response {
    fn builder() -> ResponseBuilder {
        ResponseBuilder
    }
}

impl ResponseBuilder {
    fn header(self, _name: &str, _value: impl AsRef<str>) -> Self {
        self
    }
}

fn allowlist_redirect_url(raw: &str) -> Result<String, &'static str> {
    if raw.starts_with('/') && !raw.starts_with("//") && !raw.contains('\\') && !raw.chars().any(char::is_control) {
        return Ok(raw.to_string());
    }

    let parsed = Url::parse(raw).map_err(|_| "invalid redirect")?;
    if parsed.scheme() != "https" {
        return Err("blocked redirect scheme");
    }

    let allowed_redirect_hosts = ["app.example.com", "accounts.example.com"];
    if !allowed_redirect_hosts.contains(&parsed.host_str().unwrap_or_default()) {
        return Err("blocked redirect host");
    }

    Ok(raw.to_string())
}

fn redirect_with_safe_helper(Query(params): Query<HashMap<String, String>>) -> Redirect {
    let raw = params.get("next").map(String::as_str).unwrap_or("/");
    let target = allowlist_redirect_url(raw).unwrap_or_else(|_| "/".to_string());
    Redirect::to(&target)
}

fn redirect_with_inline_local_guard(Query(params): Query<HashMap<String, String>>) -> Result<Redirect, &'static str> {
    let target = params.get("continue").cloned().unwrap_or_default();
    if !(target.starts_with('/') && !target.starts_with("//") && !target.contains('\\') && !target.chars().any(char::is_control)) {
        return Err("blocked redirect");
    }
    Ok(Redirect::temporary(&target))
}

fn location_header_with_safe_helper(req: Request) -> ResponseBuilder {
    let raw = req
        .headers()
        .get("x-return-to")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("/");
    let location = allowlist_redirect_url(raw).unwrap_or_else(|_| "/".to_string());
    Response::builder().header(LOCATION, location)
}
