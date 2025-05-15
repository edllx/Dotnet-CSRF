using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Components;

namespace edllx.dotnet.csrf;
// Middleware

public class CSRFBlazorServerMiddleware
{
  private readonly RequestDelegate _next;
  private readonly CSRFService _csrfService;

  private List<string> _protected_routes { get; }

  public CSRFBlazorServerMiddleware(RequestDelegate next, Assembly assembly, CSRFService csrfService)
  {
    _next = next;
    _csrfService = csrfService;
    _protected_routes = assembly.GetTypes()
      .SelectMany(t => t.GetCustomAttributes<RouteAttribute>())
      .Select(attr => attr.Template)
      .Distinct()
      .ToList();

    _protected_routes.Remove("/404");
    _protected_routes.Remove("/Error");

  }

  public Task Invoke(HttpContext context)
  {

    Endpoint? endpoint = context.GetEndpoint();
    if (endpoint is null)
    {
      return _next(context);
    }

    string name_path = endpoint.DisplayName ?? "";

    if (string.IsNullOrEmpty(name_path))
    {
      return handleSecondaryRequest(context);
    }

    string[] parts = name_path.Split(' ');

    if (!_protected_routes.Any(val =>
    {
      bool success = Regex.Match(val, $@"{parts.First()}$").Success;
      return success;
    }))
    {
      return _next(context);
    }

    return HandleProtectedRoute(context);
  }

  private Task HandleProtectedRoute(HttpContext context)
  {

    var (cookieToken, requestToken) = _csrfService.GenerateTokens();
    CookieOptions options = new()
    {
      HttpOnly = true,
      Secure = true,
      SameSite = SameSiteMode.None
    };

    if (!String.IsNullOrEmpty(_csrfService.DOMAIN))
    {
      options.Domain = _csrfService.DOMAIN;
    }

    context.Response.Cookies.Append(
      _csrfService.CookieName,
      cookieToken,
      options
    );

    context.Items[_csrfService.TokenName] = requestToken;
    return _next(context);
  }

  private Task handleSecondaryRequest(HttpContext context)
  {
    string cookie = context.Request.Cookies[_csrfService.CookieName] ?? "";
    context.Items[_csrfService.TokenName] = _csrfService.ComputeHmac(cookie);
    return _next(context);
  }
}

// Extension 
public static class CSRFBlazorServerBuilderExtensions
{
  public static IApplicationBuilder UseCSRFBlazorServer(this IApplicationBuilder builder)
  {
    ArgumentNullException.ThrowIfNull(builder);
    builder.VerifyCSRFServiceRegistered();
    builder.UseMiddleware<CSRFBlazorServerMiddleware>();
    return builder;
  }

  private static void VerifyCSRFServiceRegistered(this IApplicationBuilder builder)
  {
    if (builder.ApplicationServices.GetService(typeof(CSRFService)) == null)
    {
      throw new InvalidOperationException("Unable to find the required services. [ CSRFService ]");
    }
  }
}