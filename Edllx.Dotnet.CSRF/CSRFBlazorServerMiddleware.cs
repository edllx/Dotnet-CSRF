namespace edllx.dotnet.csrf;
// Middleware

public class CSRFBlazorServerMiddleware
{
  private readonly RequestDelegate _next;
  private readonly CSRFService _csrfService;

  public CSRFBlazorServerMiddleware(RequestDelegate next, CSRFService csrfService)
  {
    _next = next;
    _csrfService = csrfService;
  }

  public async Task Invoke(HttpContext context)
  {
    IConfiguration configuration = context.RequestServices.GetRequiredService<IConfiguration>();
    string CSRF_COOKIE_NAME =configuration["CSRF_COOKIE_NAME"]??throw new Exception("Missing configuration CSRF_COOKIE_NAME"); 
    string CSRF_HEADER_NAME =configuration["CSRF_HEADER_NAME"]??throw new Exception("Missing configuration CSRF_HEADER_NAME"); 
    string? DOMAIN = configuration["DOMAIN"]; 

    var (cookieToken, requestToken) = _csrfService.GenerateTokens();

    if (ShouldValidate(context))
    {
      CookieOptions options =  new(){
        HttpOnly = true,
                 Secure = true,
                 SameSite = SameSiteMode.None
      }; 

      if (!String.IsNullOrEmpty(DOMAIN)){
        options.Domain = DOMAIN;
      }

      context.Response.Cookies.Append(
          CSRF_COOKIE_NAME,
          cookieToken,
          options
          );
    }
    string cookie = context.Request.Cookies[CSRF_COOKIE_NAME] ?? "";
    context.Items[CSRF_HEADER_NAME] = _csrfService.ComputeHmac(cookie);

    await _next(context);
  }

  private bool ShouldValidate(HttpContext context)
  {
    var endpoint = context.GetEndpoint();
    return endpoint?.Metadata.GetMetadata<RequireCSRF>() != null;
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
