using System.Security.Cryptography;
using System.Text;

namespace edllx.dotnet.csrf;

public class CSRFService
{
  private readonly byte[] _secretKey;
  private readonly string _tokenName;
  private readonly string _cookieName;
  private readonly string _domain;

  internal string CookieName { get { return _cookieName; } }
  internal string TokenName { get { return _tokenName; } }
  internal string DOMAIN { get { return _domain; } }

  public CSRFService(IConfiguration config)
  {
    _secretKey = Convert.FromBase64String(config["CSRF_SECRET_KEY"] ?? throw new Exception("Missing configuration CSRF_SECRET_KEY"));
    _tokenName = config["CSRF_HEADER_NAME"] ?? throw new Exception("Missing configuration CSRF_HEADER_NAME");
    _cookieName = config["CSRF_COOKIE_NAME"] ?? throw new Exception("Missing configuration CSRF_COOKIE_NAME");
    _domain = config["DOMAIN"] ?? throw new Exception("Missing configuration DOMAIN");
  }

  public CSRFService(string secret_key, string token_name, string cookie_name, string domain)
  {
    _secretKey = Convert.FromBase64String(secret_key);
    _tokenName = token_name;
    _cookieName = cookie_name;
    _domain = domain;
  }

  public (string CookieToken, string RequestToken) GenerateTokens()
  {
    string cookieToken = GenerateRandomToken();
    string requestToken = ComputeHmac(cookieToken);
    return (cookieToken, requestToken);
  }

  internal bool ValidateTokens(string cookieToken, string requestToken)
  {
    if (string.IsNullOrEmpty(cookieToken) || string.IsNullOrEmpty(requestToken)) { return false; }

    string expectedToken = ComputeHmac(cookieToken);
    return requestToken == expectedToken;
  }

  internal string GenerateRandomToken()
  {
    byte[] bytes = new byte[32];
    using RandomNumberGenerator rng = RandomNumberGenerator.Create();
    rng.GetBytes(bytes);
    return Convert.ToBase64String(bytes);
  }

  internal string ComputeHmac(string input)
  {
    using HMACSHA256 hmac = new HMACSHA256(_secretKey);
    byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(input));
    return Convert.ToBase64String(hash);
  }
}

// Attribure
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class RequireCSRF() : Attribute
{
}
