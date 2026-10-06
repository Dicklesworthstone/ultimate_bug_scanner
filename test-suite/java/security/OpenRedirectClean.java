package security;

import java.io.IOException;
import java.net.URI;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

public final class OpenRedirectClean {
    private static final Set<String> ALLOWED_HOSTS = Set.of("app.example.com");

    private static String safeRedirectTarget(String raw) {
        URI parsed = URI.create(raw);
        if (parsed.isAbsolute()) {
            if ("https".equals(parsed.getScheme()) && ALLOWED_HOSTS.contains(parsed.getHost())) {
                return parsed.toString();
            }
            throw new IllegalArgumentException("blocked redirect");
        }
        if (parsed.getRawAuthority() != null || parsed.toString().startsWith("//")) {
            throw new IllegalArgumentException("blocked redirect authority");
        }
        String path = parsed.getPath();
        if (path == null || !path.startsWith("/") || path.startsWith("//")) {
            throw new IllegalArgumentException("blocked redirect");
        }
        return parsed.toString();
    }

    public void redirectFromQuery(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String next = safeRedirectTarget(request.getParameter("next"));
        response.sendRedirect(next);
    }

    public String springRedirect(@RequestParam("next") String next) {
        return "redirect:" + safeRedirectTarget(next);
    }

    public RedirectView redirectFromHeader(HttpServletRequest request) {
        String target = safeRedirectTarget(request.getHeader("X-Return-To"));
        return new RedirectView(target);
    }

    public ModelAndView modelAndViewRedirect(HttpServletRequest request) {
        String location = safeRedirectTarget(request.getParameter("return_to"));
        return new ModelAndView("redirect:" + location);
    }

    public ResponseEntity<Void> locationHeader(HttpServletRequest request) {
        String target = safeRedirectTarget(request.getParameter("continue"));
        return ResponseEntity.status(302).header("Location", target).build();
    }
}
