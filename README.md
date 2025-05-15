### 🔐 CSRF Protection: Signed Double-Submit Cookie

This implementation enables Cross-Site Request Forgery (CSRF) protection using the Signed Double-Submit Cookie pattern.

### 🧱 Blazor Server Setup

Configure CSRF in your Blazor Server app by registering the CSRFService:

```c#
builder.Services.AddSingleton<CSRFService>(s =>
{
    return new CSRFService(secretKey, tokenName, cookieName, domain);
});

// Add CSRF middleware
app.UseCSRFBlazorServer();
```

### 🛠️ ASP.NET Core API Setup

In your ASP.NET Core API project, register the same CSRFService with matching configuration:

```c#
builder.Services.AddSingleton<CSRFService>(s =>
{
    return new CSRFService(secretKey, tokenName, cookieName, domain);
});

// Add CSRF middleware
app.UseCSRFApi();
```

Both the server and API must use the same secret key and configuration to ensure proper validation.

### 🌱 Environment Variable Configuration

Alternatively you can use env variables

```c#
CSRF_SECRET_KEY=""
CSRF_HEADER_NAME=""
CSRF_COOKIE_NAME=""
DOMAIN=""
```

Then, load them into your application using DotNetEnv:

```c#
// Load environment variables
// Use DotNetEnv package
Env.Load();
builder.Configuration.AddEnvironmentVariables();

// Register CSRF service
builder.Services.AddSingleton<CSRFService>();
```

### 📚 Resources

- [🔗 OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

