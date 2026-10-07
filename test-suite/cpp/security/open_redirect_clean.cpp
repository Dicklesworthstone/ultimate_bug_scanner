#include <cstdlib>
#include <stdexcept>
#include <string>
#include <unordered_set>

struct Request {
    std::string get_param_value(const std::string& name) const {
        return name == "next" ? "/dashboard" : "https://app.example.com/profile";
    }

    std::string getHeader(const std::string& name) const {
        return name == "X-Return-To" ? "/settings" : "/";
    }
};

struct Response {
    void redirect(const std::string& target);
    void set_header(const std::string& name, const std::string& value);
};

std::string safe_redirect_url(const std::string& raw) {
    if (raw.find_first_of("\\\r\n\t") != std::string::npos) {
        throw std::invalid_argument("blocked redirect separator or control character");
    }
    if (raw.rfind("/", 0) == 0 && raw.rfind("//", 0) != 0) {
        return raw;
    }

    const std::unordered_set<std::string> allowed_redirect_hosts = {
        "app.example.com",
        "accounts.example.com"
    };
    const std::string prefix = "https://";
    if (raw.rfind(prefix, 0) != 0) {
        throw std::invalid_argument("blocked redirect scheme");
    }

    const auto host_end = raw.find('/', prefix.size());
    const std::string host = raw.substr(prefix.size(), host_end - prefix.size());
    if (allowed_redirect_hosts.find(host) == allowed_redirect_hosts.end()) {
        throw std::invalid_argument("blocked redirect host");
    }

    return raw;
}

void redirect_with_safe_helper(const Request& req, Response& response) {
    auto target = safe_redirect_url(req.get_param_value("next"));
    response.redirect(target);
}

void redirect_header_with_safe_helper(const Request& req, Response& response) {
    std::string target = safe_redirect_url(req.getHeader("X-Return-To"));
    response.redirect(target);
}

void redirect_with_inline_local_guard(const Request& req, Response& response) {
    auto target = req.get_param_value("continue");
    if (!(target.rfind("/", 0) == 0 && target.rfind("//", 0) != 0 &&
          target.find_first_of("\\\r\n\t") == std::string::npos)) {
        throw std::invalid_argument("blocked redirect");
    }
    response.redirect(target);
}

void redirect_location_header_with_safe_helper(Response& response) {
    const char *raw = getenv("HTTP_X_REDIRECT_URL");
    std::string location = safe_redirect_url(raw ? raw : "/");
    response.set_header("Location", location);
}
