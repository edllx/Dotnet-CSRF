namespace edllx.dotnet.csrf;

// Middleware
public class CSRFWebAppMiddleware 
{
  private readonly RequestDelegate _next;
  private readonly CSRFService _csrfService;

  public CSRFWebAppMiddleware(RequestDelegate next, CSRFService csrfService)
  {
    _next = next;
    _csrfService = csrfService;
  }

  public async Task Invoke(HttpContext context)
  {
    if (ShouldValidate(context))
    {
      string cookieToken = context.Request.Cookies[_csrfService.CookieName] ?? "";
      string headerToken = context.Request.Headers[_csrfService.TokenName].FirstOrDefault() ?? "" ;

      if (!_csrfService.ValidateTokens(cookieToken, headerToken))
      {
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Invalid CSRF token");
        return;
      }
    }
    await _next(context);
  }

  private bool ShouldValidate(HttpContext context)
  {
    var endpoint = context.GetEndpoint();
    return endpoint?.Metadata.GetMetadata<RequireCSRF>() != null;
  }
}

// Extension 
public static class CSRFApplicatoinBuilderExtensions
{
  public static IApplicationBuilder UseCSRFApi(this IApplicationBuilder builder)
  {
    ArgumentNullException.ThrowIfNull(builder);
    builder.VerifyCSRFServiceRegistered();
    builder.UseMiddleware<CSRFWebAppMiddleware>();
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
