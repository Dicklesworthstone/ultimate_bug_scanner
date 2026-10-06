using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;

public sealed class OpenRedirectClean : Controller
{
    private static readonly HashSet<string> AllowedRedirectHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "app.example.com",
        "accounts.example.com"
    };

    private static string SafeRedirectTarget(string raw)
    {
        if (Microsoft.AspNetCore.Http.HttpResults.RedirectHttpResult.IsLocalUrl(raw))
        {
            return raw;
        }

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !AllowedRedirectHosts.Contains(uri.Host))
        {
            throw new InvalidOperationException("blocked redirect");
        }

        return uri.ToString();
    }

    public IActionResult RedirectQuery(HttpRequest request)
    {
        var target = SafeRedirectTarget(request.Query["returnUrl"]!);
        return Redirect(target);
    }

    public IActionResult LocalRedirectQuery(HttpRequest request)
    {
        return LocalRedirect(request.Query["returnUrl"]!);
    }

    public IActionResult RedirectHeaderWithLocalGuard(HttpContext context)
    {
        context.Request.Headers.TryGetValue("X-Return-To", out StringValues target);
        var redirectTarget = target.ToString();
        if (!Url.IsLocalUrl(redirectTarget))
        {
            return BadRequest();
        }

        return Redirect(redirectTarget);
    }

    public void WriteLocationHeader(HttpContext context)
    {
        var destination = SafeRedirectTarget(context.Request.Cookies["destination"]!);
        context.Response.Headers["Location"] = destination;
    }

    public IActionResult RedirectRouteValue(HttpRequest request)
    {
        var callback = SafeRedirectTarget(request.RouteValues["callback"]?.ToString() ?? "/");
        return RedirectPermanent(callback);
    }
}
