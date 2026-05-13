# ASP.NET Core 10 — Auth, Filters & Middleware Guide

---

## Table of Contents

1. [Project Setup](#1-project-setup)
2. [JWT Authentication](#2-jwt-authentication)
3. [OAuth 2.0 / OpenID Connect](#3-oauth-20--openid-connect)
4. [Authorization (Roles, Policies, Claims)](#4-authorization)
5. [Custom Middleware](#5-custom-middleware)
6. [Filters (Action, Exception, Resource, Result)](#6-filters)
7. [Global Exception Handling](#7-global-exception-handling)
8. [Rate Limiting](#8-rate-limiting)
9. [CORS](#9-cors)
10. [Model Validation](#10-model-validation)
11. [Minimal APIs vs Controllers](#11-minimal-apis-vs-controllers)
12. [Refresh Token Patterns](#12-refresh-token-patterns)
13. [JWT with ASP.NET Core Identity](#13-jwt-with-aspnet-core-identity)

---

## 1. Project Setup

```bash
dotnet new webapi -n MyApi --framework net10.0
cd MyApi
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.AspNetCore.Authentication.Google   # for OAuth
dotnet add package System.IdentityModel.Tokens.Jwt
```

**`appsettings.json`** — store all secrets here (use User Secrets / env vars in production):

```json
{
  "Jwt": {
    "Key": "your-256-bit-secret-key-here-must-be-long",
    "Issuer": "https://your-api.com",
    "Audience": "https://your-api.com",
    "ExpiryMinutes": 60
  },
  "Authentication": {
    "Google": {
      "ClientId": "your-google-client-id",
      "ClientSecret": "your-google-client-secret"
    }
  }
}
```

---

## 2. JWT Authentication

### How JWT Works (Big Picture)

```
Client                        API
  |                            |
  |-- POST /auth/login ------> |
  |   { username, password }   |
  |                            |-- Validates credentials
  |                            |-- Creates JWT token
  |<-- 200 OK { token } ------ |
  |                            |
  |-- GET /api/orders -------> |
  |   Authorization: Bearer <token>
  |                            |-- Validates token signature
  |                            |-- Reads claims from token
  |<-- 200 OK { data } ------- |
```

A JWT has 3 parts separated by dots: `header.payload.signature`
- **Header**: algorithm used (HS256, RS256)
- **Payload**: claims (userId, roles, email, expiry)
- **Signature**: proves the token wasn't tampered with

### Step 1 — Create the Token Service

```csharp
// Services/TokenService.cs
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public class TokenService
{
    private readonly IConfiguration _config;

    public TokenService(IConfiguration config)
    {
        _config = config;
    }

    public string GenerateToken(string userId, string email, IList<string> roles)
    {
        // Claims are key-value pairs embedded inside the token
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, userId),
            new Claim(ClaimTypes.Email, email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // unique token ID
        };

        // Add roles as multiple claims
        foreach (var role in roles)
            claims.Add(new Claim(ClaimTypes.Role, role));

        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));

        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(
                double.Parse(_config["Jwt:ExpiryMinutes"]!)),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
```

### Step 2 — Register JWT in Program.cs

```csharp
// Program.cs
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Register TokenService for DI
builder.Services.AddScoped<TokenService>();

// Configure JWT Authentication
builder.Services.AddAuthentication(options =>
{
    // Set JWT as the default scheme for everything
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,           // Check the "iss" claim
        ValidateAudience = true,         // Check the "aud" claim
        ValidateLifetime = true,         // Reject expired tokens
        ValidateIssuerSigningKey = true, // Verify the signature

        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),

        ClockSkew = TimeSpan.Zero        // No grace period — token expiry is exact
    };

    // Optional: capture auth events for logging
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = ctx =>
        {
            Console.WriteLine($"Auth failed: {ctx.Exception.Message}");
            return Task.CompletedTask;
        },
        OnTokenValidated = ctx =>
        {
            // Token is valid — ctx.Principal has the claims
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthorization();
builder.Services.AddControllers();

var app = builder.Build();

// ORDER MATTERS — authentication must come before authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();
```

### Step 3 — Auth Controller (Login → Token)

```csharp
// Controllers/AuthController.cs
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly TokenService _tokenService;

    public AuthController(TokenService tokenService)
    {
        _tokenService = tokenService;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        // TODO: Replace with real DB lookup + password hash check
        if (request.Username != "admin" || request.Password != "password123")
            return Unauthorized(new { message = "Invalid credentials" });

        var token = _tokenService.GenerateToken(
            userId: "user-001",
            email: "admin@example.com",
            roles: ["Admin", "User"]
        );

        return Ok(new { token, expiresIn = 3600 });
    }
}

public record LoginRequest(string Username, string Password);
```

### Step 4 — Protect an Endpoint

```csharp
// Controllers/OrdersController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

[ApiController]
[Route("api/[controller]")]
[Authorize]  // <-- Requires a valid JWT on every action in this controller
public class OrdersController : ControllerBase
{
    [HttpGet]
    public IActionResult GetOrders()
    {
        // Read claims from the validated token
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email  = User.FindFirst(ClaimTypes.Email)?.Value;

        return Ok(new { userId, email, orders = new[] { "Order1", "Order2" } });
    }

    [HttpGet("admin-only")]
    [Authorize(Roles = "Admin")]  // Only users with the Admin role
    public IActionResult AdminEndpoint()
    {
        return Ok(new { message = "You are an admin!" });
    }

    [HttpGet("public")]
    [AllowAnonymous]  // Overrides [Authorize] on the controller — no token needed
    public IActionResult PublicEndpoint()
    {
        return Ok(new { message = "Anyone can see this" });
    }
}
```

---

## 3. OAuth 2.0 / OpenID Connect

OAuth lets users log in via a third-party (Google, GitHub, Microsoft) instead of a password you manage.

### How OAuth Flow Works

```
User                  Your API               Google
  |                      |                      |
  |-- Click "Login       |                      |
  |   with Google" ----> |                      |
  |                      |-- Redirect to -----> |
  |                      |   accounts.google.com|
  |<------------------------------------------  |
  |        Google login page                     |
  |-- Login at Google -----------------------> |
  |<-- Redirect back to /auth/google/callback   |
  |           with ?code=xyz                    |
  |                      |                      |
  |-- GET /auth/google/  |                      |
  |   callback?code=xyz->|                      |
  |                      |-- Exchange code for->|
  |                      |   access_token       |
  |                      |<-- user profile -----|
  |                      |-- Create YOUR JWT    |
  |<-- Your JWT token -- |                      |
```

### Setup (Google OAuth)

```csharp
// Program.cs — add alongside JWT setup
builder.Services.AddAuthentication(...)
    .AddJwtBearer(...)           // existing JWT setup
    .AddGoogle(options =>
    {
        options.ClientId     = builder.Configuration["Authentication:Google:ClientId"]!;
        options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"]!;
        options.CallbackPath = "/auth/google/callback";   // must match Google Console setting

        // Request extra scopes beyond the default profile
        options.Scope.Add("email");
        options.Scope.Add("profile");

        options.SaveTokens = true; // Save Google's tokens if you need them later
    });
```

### Google OAuth Controller

```csharp
// Controllers/GoogleAuthController.cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

[ApiController]
[Route("auth")]
public class GoogleAuthController : ControllerBase
{
    private readonly TokenService _tokenService;

    public GoogleAuthController(TokenService tokenService)
    {
        _tokenService = tokenService;
    }

    // Step 1: Redirect user to Google
    [HttpGet("google")]
    public IActionResult LoginWithGoogle()
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(GoogleCallback))
        };
        return Challenge(properties, GoogleDefaults.AuthenticationScheme);
    }

    // Step 2: Google sends the user back here after login
    [HttpGet("google/callback")]
    public async Task<IActionResult> GoogleCallback()
    {
        // Authenticate using the Google cookie set by middleware
        var result = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);

        if (!result.Succeeded)
            return Unauthorized(new { message = "Google authentication failed" });

        // Extract user info from Google's claims
        var googleId = result.Principal!.FindFirst(ClaimTypes.NameIdentifier)?.Value!;
        var email    = result.Principal.FindFirst(ClaimTypes.Email)?.Value!;
        var name     = result.Principal.FindFirst(ClaimTypes.Name)?.Value!;

        // TODO: Find or create the user in your database here

        // Issue YOUR application's JWT (not Google's token)
        var token = _tokenService.GenerateToken(
            userId: googleId,
            email: email,
            roles: ["User"]
        );

        // In a real app, redirect to your frontend with the token
        return Ok(new { token, email, name });
    }
}
```

---

## 4. Authorization

Authorization answers: "What is this user allowed to do?"

### Roles — Simple Role-Based Access

```csharp
[Authorize(Roles = "Admin")]          // Single role
[Authorize(Roles = "Admin,Manager")] // Either role (OR)

// Both must match (AND) — stack two attributes
[Authorize(Roles = "Admin")]
[Authorize(Roles = "Manager")]
```

### Policies — Flexible Rule Sets

Policies let you write any logic, not just role checks.

```csharp
// Program.cs
builder.Services.AddAuthorization(options =>
{
    // Policy: user must have a specific claim
    options.AddPolicy("MustBeAdult", policy =>
        policy.RequireClaim("age_verified", "true"));

    // Policy: user must have one of these roles
    options.AddPolicy("AdminOrManager", policy =>
        policy.RequireRole("Admin", "Manager"));

    // Policy: multiple requirements (all must pass)
    options.AddPolicy("SeniorEmployee", policy =>
    {
        policy.RequireRole("Employee");
        policy.RequireClaim("department", "Engineering");
    });

    // Policy: completely custom requirement (see below)
    options.AddPolicy("MinimumAgePolicy", policy =>
        policy.Requirements.Add(new MinimumAgeRequirement(18)));
});
```

**Use a policy on an endpoint:**

```csharp
[Authorize(Policy = "AdminOrManager")]
public IActionResult SensitiveAction() { ... }
```

### Custom Authorization Requirements

When built-in checks aren't enough, create your own:

```csharp
// Requirements/MinimumAgeRequirement.cs
using Microsoft.AspNetCore.Authorization;

// 1. The requirement — just holds the data
public class MinimumAgeRequirement : IAuthorizationRequirement
{
    public int MinimumAge { get; }
    public MinimumAgeRequirement(int minimumAge) => MinimumAge = minimumAge;
}

// 2. The handler — contains the actual logic
public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MinimumAgeRequirement requirement)
    {
        var ageClaim = context.User.FindFirst("birthdate")?.Value;

        if (ageClaim is null)
        {
            context.Fail(); // No claim = fail
            return Task.CompletedTask;
        }

        var birthDate = DateTime.Parse(ageClaim);
        var age = DateTime.Today.Year - birthDate.Year;

        if (age >= requirement.MinimumAge)
            context.Succeed(requirement); // Pass!
        else
            context.Fail();

        return Task.CompletedTask;
    }
}
```

```csharp
// Register the handler in Program.cs
builder.Services.AddScoped<IAuthorizationHandler, MinimumAgeHandler>();
```

### Resource-Based Authorization

When the decision depends on the specific object (e.g., "can this user edit THIS post?"):

```csharp
// Requirements/DocumentOwnerRequirement.cs
public class DocumentOwnerRequirement : IAuthorizationRequirement { }

public class DocumentOwnerHandler
    : AuthorizationHandler<DocumentOwnerRequirement, Document>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        DocumentOwnerRequirement requirement,
        Document document)   // <-- the specific resource
    {
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (document.OwnerId == userId)
            context.Succeed(requirement);

        return Task.CompletedTask;
    }
}
```

```csharp
// Usage in controller
[HttpDelete("{id}")]
[Authorize]
public async Task<IActionResult> DeleteDocument(string id)
{
    var document = await _db.Documents.FindAsync(id);
    if (document is null) return NotFound();

    // Check if the current user owns this specific document
    var authResult = await _authorizationService
        .AuthorizeAsync(User, document, new DocumentOwnerRequirement());

    if (!authResult.Succeeded)
        return Forbid(); // 403

    _db.Documents.Remove(document);
    await _db.SaveChangesAsync();
    return NoContent();
}
```

---

## 5. Custom Middleware

Middleware runs on every request in a pipeline — each piece can inspect/modify the request, call the next piece, and then inspect/modify the response.

```
Request ──► MW1 ──► MW2 ──► MW3 ──► Controller
                                       │
Response ◄── MW1 ◄── MW2 ◄── MW3 ◄────┘
```

### Basic Middleware Anatomy

```csharp
// Middleware/RequestLoggingMiddleware.cs
public class RequestLoggingMiddleware
{
    // RequestDelegate is a function: "call the next middleware"
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestLoggingMiddleware> _logger;

    public RequestLoggingMiddleware(
        RequestDelegate next,
        ILogger<RequestLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    // InvokeAsync is called for every HTTP request
    public async Task InvokeAsync(HttpContext context)
    {
        // ── BEFORE the rest of the pipeline ──────────────────
        var start = DateTime.UtcNow;
        _logger.LogInformation(
            "[REQ] {Method} {Path}",
            context.Request.Method,
            context.Request.Path);

        // Call the next middleware (or the controller if this is last)
        await _next(context);

        // ── AFTER the rest of the pipeline ───────────────────
        var duration = DateTime.UtcNow - start;
        _logger.LogInformation(
            "[RES] {Method} {Path} → {StatusCode} ({Duration}ms)",
            context.Request.Method,
            context.Request.Path,
            context.Response.StatusCode,
            duration.TotalMilliseconds);
    }
}

// Extension method — makes registration cleaner
public static class RequestLoggingMiddlewareExtensions
{
    public static IApplicationBuilder UseRequestLogging(
        this IApplicationBuilder app) =>
        app.UseMiddleware<RequestLoggingMiddleware>();
}
```

```csharp
// Program.cs
app.UseRequestLogging(); // your custom middleware
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
```

### Middleware with Short-Circuit (Block Early)

```csharp
// Middleware/ApiKeyMiddleware.cs
// Blocks requests missing a valid API key, without going further
public class ApiKeyMiddleware
{
    private const string ApiKeyHeader = "X-Api-Key";
    private readonly RequestDelegate _next;
    private readonly IConfiguration _config;

    public ApiKeyMiddleware(RequestDelegate next, IConfiguration config)
    {
        _next = next;
        _config = config;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Allow health checks through without an API key
        if (context.Request.Path.StartsWithSegments("/health"))
        {
            await _next(context);
            return;
        }

        var hasKey = context.Request.Headers.TryGetValue(ApiKeyHeader, out var key);

        if (!hasKey || key != _config["ApiKey"])
        {
            // Short-circuit: respond immediately, don't call _next
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "Missing or invalid API key"
            });
            return; // Pipeline stops here
        }

        await _next(context); // Valid key — continue
    }
}
```

### Middleware with Request Body Reading

```csharp
// Middleware/RequestBodyMiddleware.cs
// Reads & logs the request body (useful for auditing)
public class RequestBodyMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestBodyMiddleware> _logger;

    public RequestBodyMiddleware(RequestDelegate next,
        ILogger<RequestBodyMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Enable buffering so the body can be read multiple times
        context.Request.EnableBuffering();

        var body = await new StreamReader(context.Request.Body).ReadToEndAsync();
        context.Request.Body.Position = 0; // Reset for the controller to read again

        _logger.LogDebug("Request body: {Body}", body);

        await _next(context);
    }
}
```

---

## 6. Filters

Filters are like middleware but run at different points in the MVC action pipeline. Use filters for concerns tied to controllers/actions (like validation, auditing specific actions).

```
Request → Middleware → [Resource Filter] → [Action Filter: Before]
                                            → [Controller Action]
                                           ← [Action Filter: After]
                        [Exception Filter] (if exception thrown)
                       ← [Result Filter]
Response ← Middleware
```

### Action Filter — Before/After an Action Runs

```csharp
// Filters/LogActionFilter.cs
using Microsoft.AspNetCore.Mvc.Filters;

public class LogActionFilter : IActionFilter  // or IAsyncActionFilter for async
{
    private readonly ILogger<LogActionFilter> _logger;

    public LogActionFilter(ILogger<LogActionFilter> logger)
    {
        _logger = logger;
    }

    // Runs BEFORE the action method
    public void OnActionExecuting(ActionExecutingContext context)
    {
        _logger.LogInformation(
            "Executing action: {Action} with args: {@Args}",
            context.ActionDescriptor.DisplayName,
            context.ActionArguments);
    }

    // Runs AFTER the action method
    public void OnActionExecuted(ActionExecutedContext context)
    {
        _logger.LogInformation(
            "Executed action: {Action} → result: {Result}",
            context.ActionDescriptor.DisplayName,
            context.Result?.GetType().Name);
    }
}
```

### Exception Filter — Catch Unhandled Exceptions in Actions

```csharp
// Filters/GlobalExceptionFilter.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

public class GlobalExceptionFilter : IExceptionFilter
{
    private readonly ILogger<GlobalExceptionFilter> _logger;

    public GlobalExceptionFilter(ILogger<GlobalExceptionFilter> logger)
    {
        _logger = logger;
    }

    public void OnException(ExceptionContext context)
    {
        _logger.LogError(context.Exception, "Unhandled exception");

        var (statusCode, message) = context.Exception switch
        {
            KeyNotFoundException  => (404, "Resource not found"),
            UnauthorizedAccessException => (403, "Access denied"),
            ArgumentException ex => (400, ex.Message),
            _                    => (500, "An unexpected error occurred")
        };

        context.Result = new ObjectResult(new { error = message })
        {
            StatusCode = statusCode
        };

        context.ExceptionHandled = true; // Don't propagate further
    }
}
```

### Resource Filter — Runs Before Model Binding

Useful for caching: you can return a cached response before the action even runs.

```csharp
// Filters/CacheFilter.cs
public class CacheFilter : IResourceFilter
{
    private static readonly Dictionary<string, object> _cache = new();

    public void OnResourceExecuting(ResourceExecutingContext context)
    {
        var key = context.HttpContext.Request.Path;
        if (_cache.TryGetValue(key, out var cached))
        {
            // Short-circuit: return cached result immediately
            context.Result = new OkObjectResult(cached);
        }
    }

    public void OnResourceExecuted(ResourceExecutedContext context)
    {
        var key = context.HttpContext.Request.Path;
        if (context.Result is OkObjectResult ok && ok.Value is not null)
            _cache[key] = ok.Value; // Store result in cache
    }
}
```

### Result Filter — Wraps the Response

```csharp
// Filters/WrapResponseFilter.cs
// Wraps every action result in a standard envelope: { success, data, timestamp }
public class WrapResponseFilter : IResultFilter
{
    public void OnResultExecuting(ResultExecutingContext context)
    {
        if (context.Result is ObjectResult objectResult)
        {
            objectResult.Value = new
            {
                success = true,
                data = objectResult.Value,
                timestamp = DateTime.UtcNow
            };
        }
    }

    public void OnResultExecuted(ResultExecutedContext context) { }
}
```

### Register Filters — Three Ways

**Way 1: Globally (applies to all controllers)**
```csharp
// Program.cs
builder.Services.AddControllers(options =>
{
    options.Filters.Add<LogActionFilter>();       // by type (uses DI)
    options.Filters.Add<GlobalExceptionFilter>();
});
```

**Way 2: On a controller or action (attribute)**
```csharp
[ServiceFilter(typeof(LogActionFilter))]  // resolves from DI
[TypeFilter(typeof(CacheFilter))]         // instantiated by framework (also DI)
public class ProductsController : ControllerBase { ... }
```

**Way 3: As a simple attribute (no DI needed)**
```csharp
public class ValidateModelAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        if (!context.ModelState.IsValid)
        {
            context.Result = new BadRequestObjectResult(context.ModelState);
        }
    }
}

// Usage:
[HttpPost]
[ValidateModel]   // apply to a single action
public IActionResult Create([FromBody] CreateOrderRequest request) { ... }
```

---

## 7. Global Exception Handling

The modern way in .NET 8+ (still valid in .NET 10):

```csharp
// ExceptionHandlers/GlobalExceptionHandler.cs
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class GlobalExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;

    public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        _logger.LogError(exception, "Exception: {Message}", exception.Message);

        var (statusCode, title) = exception switch
        {
            KeyNotFoundException    => (404, "Not Found"),
            UnauthorizedAccessException => (403, "Forbidden"),
            ArgumentException       => (400, "Bad Request"),
            _                       => (500, "Internal Server Error")
        };

        var problem = new ProblemDetails
        {
            Title  = title,
            Status = statusCode,
            Detail = exception.Message,
            Instance = httpContext.Request.Path
        };

        httpContext.Response.StatusCode = statusCode;
        await httpContext.Response.WriteAsJsonAsync(problem, cancellationToken);

        return true; // true = exception handled; false = let it propagate
    }
}
```

```csharp
// Program.cs
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();

var app = builder.Build();
app.UseExceptionHandler(); // Enable the handler
```

---

## 8. Rate Limiting

Prevents abuse by limiting how many requests a client can make.

```csharp
// Program.cs
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // Fixed window: 10 requests per minute per IP
    options.AddFixedWindowLimiter("fixed", limiterOptions =>
    {
        limiterOptions.PermitLimit = 10;
        limiterOptions.Window = TimeSpan.FromMinutes(1);
        limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        limiterOptions.QueueLimit = 2; // allow 2 to wait in queue
    });

    // Sliding window: smoother than fixed window
    options.AddSlidingWindowLimiter("sliding", limiterOptions =>
    {
        limiterOptions.PermitLimit = 20;
        limiterOptions.Window = TimeSpan.FromMinutes(1);
        limiterOptions.SegmentsPerWindow = 4; // divide window into 4 segments
        limiterOptions.QueueLimit = 0;
    });
});
```

```csharp
// Apply globally or per-endpoint
app.UseRateLimiter();

// Per-endpoint:
app.MapControllers().RequireRateLimiting("fixed");

// On specific action:
[EnableRateLimiting("sliding")]
[HttpPost("login")]
public IActionResult Login(...) { }
```

---

## 9. CORS

Cross-Origin Resource Sharing — controls which frontend domains can call your API.

```csharp
// Program.cs
builder.Services.AddCors(options =>
{
    // Restrictive policy for production
    options.AddPolicy("ProductionPolicy", policy =>
        policy.WithOrigins("https://myapp.com", "https://www.myapp.com")
              .WithMethods("GET", "POST", "PUT", "DELETE")
              .WithHeaders("Authorization", "Content-Type")
              .AllowCredentials());

    // Open policy for development only
    options.AddPolicy("DevPolicy", policy =>
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader());
});

var app = builder.Build();

var policy = app.Environment.IsDevelopment() ? "DevPolicy" : "ProductionPolicy";
app.UseCors(policy);
```

---

## 10. Model Validation

Validate incoming request data automatically using Data Annotations.

```csharp
// Models/CreateProductRequest.cs
using System.ComponentModel.DataAnnotations;

public class CreateProductRequest
{
    [Required(ErrorMessage = "Name is required")]
    [StringLength(100, MinimumLength = 2)]
    public string Name { get; set; } = default!;

    [Required]
    [Range(0.01, 99999.99, ErrorMessage = "Price must be between 0.01 and 99999.99")]
    public decimal Price { get; set; }

    [Required]
    [Range(0, int.MaxValue, ErrorMessage = "Stock cannot be negative")]
    public int Stock { get; set; }

    [EmailAddress]
    public string? SupplierEmail { get; set; }

    [Url]
    public string? ImageUrl { get; set; }
}
```

```csharp
// Enable automatic 400 responses on invalid models
builder.Services.AddControllers()
    .ConfigureApiBehaviorOptions(options =>
    {
        options.InvalidModelStateResponseFactory = context =>
        {
            var errors = context.ModelState
                .Where(e => e.Value?.Errors.Count > 0)
                .ToDictionary(
                    k => k.Key,
                    v => v.Value!.Errors.Select(e => e.ErrorMessage).ToArray()
                );

            return new BadRequestObjectResult(new { errors });
        };
    });
```

### Custom Validation Attribute

```csharp
public class FutureDateAttribute : ValidationAttribute
{
    public override bool IsValid(object? value)
    {
        if (value is DateTime date)
            return date > DateTime.UtcNow;
        return false;
    }

    public override string FormatErrorMessage(string name) =>
        $"{name} must be a future date.";
}

// Usage:
public class CreateEventRequest
{
    [FutureDate]
    public DateTime EventDate { get; set; }
}
```

---

## 11. Minimal APIs vs Controllers

.NET supports both styles. For a new API, consider Minimal APIs for simple endpoints.

```csharp
// Program.cs — Minimal API style
var app = builder.Build();

// Simple endpoint
app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));

// With auth
app.MapGet("/me", (ClaimsPrincipal user) =>
{
    var email = user.FindFirst(ClaimTypes.Email)?.Value;
    return Results.Ok(new { email });
})
.RequireAuthorization();  // equivalent of [Authorize]

// With rate limiting + auth
app.MapPost("/orders", async (CreateOrderRequest req, OrderService svc) =>
{
    var order = await svc.CreateAsync(req);
    return Results.Created($"/orders/{order.Id}", order);
})
.RequireAuthorization("AdminOrManager")
.RequireRateLimiting("fixed");
```

---

## Key Ordering in Program.cs

**Order matters.** Here is the correct sequence:

```csharp
var app = builder.Build();

app.UseExceptionHandler();   // 1. Catch all unhandled exceptions
app.UseHttpsRedirection();   // 2. Force HTTPS
app.UseCors();               // 3. CORS headers (before auth)
app.UseRateLimiter();        // 4. Rate limiting
app.UseAuthentication();     // 5. Who are you? (reads JWT)
app.UseAuthorization();      // 6. What can you do?
// app.UseYourCustomMiddleware(); — goes here
app.MapControllers();        // 7. Route to controllers

app.Run();
```

---

## 12. Refresh Token Patterns

### Why Refresh Tokens?

Access tokens (JWTs) are short-lived (15–60 min) for security. If they expire, the user would have to log in again — bad UX. A **refresh token** is a long-lived, opaque token stored server-side that lets the client silently get a new access token without re-entering credentials.

```
Client                              API                          DB
  |                                  |                            |
  |-- POST /auth/login ------------> |                            |
  |<-- { accessToken, refreshToken } |-- store refreshToken ----> |
  |                                  |                            |
  |  ... time passes, JWT expires ...|                            |
  |                                  |                            |
  |-- POST /auth/refresh ----------> |                            |
  |   { refreshToken: "abc..." }     |-- lookup refreshToken ---> |
  |                                  |<-- valid, not expired ----- |
  |                                  |-- rotate: delete old ----> |
  |                                  |-- store new token -------> |
  |<-- { newAccessToken,             |                            |
  |       newRefreshToken }          |                            |
```

Key rules:
- Refresh tokens are **rotated** on every use (old one deleted, new one issued) — prevents replay attacks
- Refresh tokens are stored **hashed** in the DB (never plain text)
- If a refresh token is used twice (stolen + reused), **revoke the entire family**

---

### Step 1 — Database Entity

```csharp
// Models/RefreshToken.cs
public class RefreshToken
{
    public int Id { get; set; }
    public string UserId { get; set; } = default!;

    // Stored as SHA-256 hash — never the raw token
    public string TokenHash { get; set; } = default!;

    // Each login session shares a FamilyId — used to detect theft
    public string FamilyId { get; set; } = default!;

    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool IsRevoked { get; set; } = false;

    // Track which device/browser this token was issued to
    public string? DeviceInfo { get; set; }
}
```

```csharp
// Data/AppDbContext.cs
public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<RefreshToken>(entity =>
        {
            entity.HasIndex(t => t.TokenHash).IsUnique();
            entity.HasIndex(t => t.UserId);
            entity.HasIndex(t => t.FamilyId);
        });
    }
}
```

---

### Step 2 — TokenService with Refresh Token Support

```csharp
// Services/TokenService.cs
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

public class TokenService
{
    private readonly IConfiguration _config;
    private readonly AppDbContext _db;

    public TokenService(IConfiguration config, AppDbContext db)
    {
        _config = config;
        _db = db;
    }

    // ── Access Token (JWT) ─────────────────────────────────────────────────

    public string GenerateAccessToken(string userId, string email, IList<string> roles)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId),
            new(ClaimTypes.Email, email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };
        foreach (var role in roles)
            claims.Add(new Claim(ClaimTypes.Role, role));

        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            // Short-lived: 15 minutes is a common choice
            expires: DateTime.UtcNow.AddMinutes(15),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    // ── Refresh Token ──────────────────────────────────────────────────────

    // Generate a cryptographically random opaque token (not a JWT)
    private static string GenerateRawRefreshToken()
    {
        var bytes = new byte[64]; // 512 bits of randomness
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes);
    }

    // Hash the token before storing — if DB is breached, tokens are useless
    private static string HashToken(string token)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToBase64String(bytes);
    }

    // Issue a brand new refresh token for a user (on first login)
    public async Task<string> CreateRefreshTokenAsync(
        string userId, string? deviceInfo = null)
    {
        var raw = GenerateRawRefreshToken();
        var familyId = Guid.NewGuid().ToString(); // New family for each login session

        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = userId,
            TokenHash = HashToken(raw),
            FamilyId = familyId,
            ExpiresAt = DateTime.UtcNow.AddDays(
                int.Parse(_config["Jwt:RefreshTokenExpiryDays"]!)),
            DeviceInfo = deviceInfo
        });

        await _db.SaveChangesAsync();
        return raw; // Return the raw token to the client
    }

    // Rotate: validate the incoming token, invalidate it, issue a new one
    public async Task<(string newAccessToken, string newRefreshToken)?> RotateRefreshTokenAsync(
        string incomingRawToken, string? deviceInfo = null)
    {
        var hash = HashToken(incomingRawToken);

        var existing = await _db.RefreshTokens
            .FirstOrDefaultAsync(t => t.TokenHash == hash);

        // Token not found at all — reject
        if (existing is null)
            return null;

        // TOKEN REUSE DETECTED — someone is using an already-rotated token
        // This means the token family may be compromised — revoke everything
        if (existing.IsRevoked)
        {
            await RevokeEntireFamilyAsync(existing.FamilyId);
            return null;
        }

        // Token expired — reject
        if (existing.ExpiresAt < DateTime.UtcNow)
        {
            existing.IsRevoked = true;
            await _db.SaveChangesAsync();
            return null;
        }

        // ── Valid token: rotate ────────────────────────────────────────────

        // 1. Revoke the old token
        existing.IsRevoked = true;

        // 2. Issue a new refresh token in the SAME family
        var newRaw = GenerateRawRefreshToken();
        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = existing.UserId,
            TokenHash = HashToken(newRaw),
            FamilyId = existing.FamilyId, // Same family
            ExpiresAt = DateTime.UtcNow.AddDays(
                int.Parse(_config["Jwt:RefreshTokenExpiryDays"]!)),
            DeviceInfo = deviceInfo ?? existing.DeviceInfo
        });

        await _db.SaveChangesAsync();

        // 3. Need user's email + roles to issue new access token
        // In a real app, load user from DB here
        var newAccessToken = GenerateAccessToken(
            existing.UserId, "user@example.com", ["User"]);

        return (newAccessToken, newRaw);
    }

    // Revoke all tokens in a family (call this on logout or theft detection)
    public async Task RevokeEntireFamilyAsync(string familyId)
    {
        var tokens = await _db.RefreshTokens
            .Where(t => t.FamilyId == familyId && !t.IsRevoked)
            .ToListAsync();

        foreach (var t in tokens)
            t.IsRevoked = true;

        await _db.SaveChangesAsync();
    }

    // Revoke all tokens for a user (call on password change, account lock, logout-all)
    public async Task RevokeAllUserTokensAsync(string userId)
    {
        var tokens = await _db.RefreshTokens
            .Where(t => t.UserId == userId && !t.IsRevoked)
            .ToListAsync();

        foreach (var t in tokens)
            t.IsRevoked = true;

        await _db.SaveChangesAsync();
    }

    // Validate an expired JWT and extract its claims (used during refresh flow)
    public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
    {
        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = false, // ← allow expired tokens here
            ValidIssuer = _config["Jwt:Issuer"],
            ValidAudience = _config["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_config["Jwt:Key"]!))
        };

        try
        {
            var principal = new JwtSecurityTokenHandler()
                .ValidateToken(token, parameters, out var validated);

            // Ensure it's actually a JWT, not some other token type
            if (validated is not JwtSecurityToken jwt ||
                !jwt.Header.Alg.Equals(
                    SecurityAlgorithms.HmacSha256,
                    StringComparison.InvariantCultureIgnoreCase))
                return null;

            return principal;
        }
        catch
        {
            return null;
        }
    }
}
```

---

### Step 3 — Auth Controller with Refresh Endpoints

```csharp
// Controllers/AuthController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly TokenService _tokenService;

    public AuthController(TokenService tokenService)
    {
        _tokenService = tokenService;
    }

    // ── Login ──────────────────────────────────────────────────────────────
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        // TODO: replace with real DB lookup + BCrypt.Verify()
        if (request.Username != "admin" || request.Password != "password123")
            return Unauthorized(new { message = "Invalid credentials" });

        var userId = "user-001";
        var email  = "admin@example.com";
        var roles  = new[] { "Admin", "User" };

        var accessToken  = _tokenService.GenerateAccessToken(userId, email, roles);

        var deviceInfo   = Request.Headers.UserAgent.ToString();
        var refreshToken = await _tokenService.CreateRefreshTokenAsync(userId, deviceInfo);

        // Send refresh token in HttpOnly cookie — never in response body
        // HttpOnly = JS cannot read it, Secure = HTTPS only, SameSite = CSRF protection
        Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure   = true,
            SameSite = SameSiteMode.Strict,
            Expires  = DateTimeOffset.UtcNow.AddDays(7)
        });

        return Ok(new
        {
            accessToken,
            expiresIn = 900 // 15 minutes in seconds
            // refreshToken intentionally NOT in the body
        });
    }

    // ── Refresh ────────────────────────────────────────────────────────────
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh()
    {
        // Read refresh token from the HttpOnly cookie
        var incomingRefreshToken = Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(incomingRefreshToken))
            return Unauthorized(new { message = "No refresh token" });

        var deviceInfo = Request.Headers.UserAgent.ToString();
        var result = await _tokenService.RotateRefreshTokenAsync(
            incomingRefreshToken, deviceInfo);

        if (result is null)
        {
            // Invalid, expired, or reuse detected — force re-login
            Response.Cookies.Delete("refreshToken");
            return Unauthorized(new { message = "Invalid or expired refresh token" });
        }

        var (newAccessToken, newRefreshToken) = result.Value;

        // Rotate the cookie
        Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure   = true,
            SameSite = SameSiteMode.Strict,
            Expires  = DateTimeOffset.UtcNow.AddDays(7)
        });

        return Ok(new { accessToken = newAccessToken, expiresIn = 900 });
    }

    // ── Logout (current device) ────────────────────────────────────────────
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var incomingRefreshToken = Request.Cookies["refreshToken"];

        if (!string.IsNullOrEmpty(incomingRefreshToken))
        {
            // Revoke just this device's family
            var hash = /* TokenService.HashToken is private, expose a method or */ null;
            // In practice: expose RevokeByRawTokenAsync(string rawToken) on TokenService
        }

        Response.Cookies.Delete("refreshToken");
        return NoContent();
    }

    // ── Logout all devices ─────────────────────────────────────────────────
    [HttpPost("logout-all")]
    [Authorize]
    public async Task<IActionResult> LogoutAll()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value!;
        await _tokenService.RevokeAllUserTokensAsync(userId);

        Response.Cookies.Delete("refreshToken");
        return NoContent();
    }
}

public record LoginRequest(string Username, string Password);
```

---

### Step 4 — appsettings.json additions

```json
{
  "Jwt": {
    "Key": "your-256-bit-secret-key-here-must-be-long",
    "Issuer": "https://your-api.com",
    "Audience": "https://your-api.com",
    "ExpiryMinutes": 15,
    "RefreshTokenExpiryDays": 7
  }
}
```

---

### Step 5 — Cleanup Job (Prune Expired Tokens)

Expired/revoked tokens accumulate in the DB — prune them periodically.

```csharp
// BackgroundServices/TokenCleanupService.cs
public class TokenCleanupService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<TokenCleanupService> _logger;

    public TokenCleanupService(
        IServiceScopeFactory scopeFactory,
        ILogger<TokenCleanupService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromHours(6), stoppingToken); // run every 6 hours

            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            var cutoff = DateTime.UtcNow.AddDays(-7); // keep 7 days of history
            var deleted = await db.RefreshTokens
                .Where(t => t.IsRevoked || t.ExpiresAt < DateTime.UtcNow)
                .Where(t => t.CreatedAt < cutoff)
                .ExecuteDeleteAsync(stoppingToken); // EF Core 7+ bulk delete

            _logger.LogInformation("Pruned {Count} expired refresh tokens", deleted);
        }
    }
}
```

```csharp
// Program.cs
builder.Services.AddHostedService<TokenCleanupService>();
```

---

### Refresh Token Flow — Visual Summary

```
Login              Refresh                    Theft Detected
─────              ───────                    ──────────────
Issue AT + RT1     Client sends RT1           Attacker uses old RT1 (already rotated)
Store Hash(RT1)    Validate Hash(RT1) ✓        Hash(RT1) found but IsRevoked = true
                   Mark RT1 IsRevoked = true   → Revoke entire family
                   Issue AT2 + RT2             → Force re-login on all devices
                   Store Hash(RT2)             → Log security event
```

---

## 13. JWT with ASP.NET Core Identity

ASP.NET Core Identity is a full membership system: user accounts, password hashing, roles, lockout, email confirmation — all built in. Combined with JWT, it removes the need to write your own user/password management code.

### How It Differs from Raw JWT

| Raw JWT (Section 2) | JWT + Identity |
|---------------------|----------------|
| You manage users/passwords | Identity manages it |
| Manual password hashing | BCrypt-based hashing built in |
| Roles in config/code | Roles stored in DB, managed via API |
| No account lockout | Auto-lockout after N failed attempts |
| No email confirmation | Built-in email confirmation + reset |

---

### Step 1 — Install Packages

```bash
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.SqlServer   # or .Sqlite for dev
dotnet add package Microsoft.EntityFrameworkCore.Tools
```

---

### Step 2 — AppDbContext with Identity

```csharp
// Data/AppDbContext.cs
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

// Extend IdentityDbContext — it adds all Identity tables automatically:
// AspNetUsers, AspNetRoles, AspNetUserRoles, AspNetUserClaims, etc.
public class AppDbContext : IdentityDbContext<AppUser>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    // Your own tables go here
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
}
```

```csharp
// Models/AppUser.cs
using Microsoft.AspNetCore.Identity;

// Extend IdentityUser to add your own columns
public class AppUser : IdentityUser
{
    // IdentityUser already has: Id, UserName, Email, PasswordHash,
    //   PhoneNumber, EmailConfirmed, LockoutEnabled, AccessFailedCount, etc.

    // Add your own fields:
    public string? FirstName { get; set; }
    public string? LastName  { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
```

---

### Step 3 — Register Identity + JWT in Program.cs

```csharp
// Program.cs
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// 1. Database
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// 2. Identity — plug in your AppUser and AppDbContext
builder.Services.AddIdentity<AppUser, IdentityRole>(options =>
{
    // Password rules
    options.Password.RequireDigit           = true;
    options.Password.RequiredLength         = 8;
    options.Password.RequireUppercase       = true;
    options.Password.RequireNonAlphanumeric = true;

    // Lockout: lock for 5 min after 5 failed attempts
    options.Lockout.DefaultLockoutTimeSpan  = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers      = true;

    // Require unique email
    options.User.RequireUniqueEmail = true;

    // Require email confirmation before login (set false for dev)
    options.SignIn.RequireConfirmedEmail = false;
})
.AddEntityFrameworkStores<AppDbContext>()  // persist to DB
.AddDefaultTokenProviders();               // for email confirm, password reset

// 3. JWT — same as before
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme    = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer           = true,
        ValidateAudience         = true,
        ValidateLifetime         = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer    = builder.Configuration["Jwt:Issuer"],
        ValidAudience  = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorization();
builder.Services.AddScoped<TokenService>();
builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
```

---

### Step 4 — Run Migrations

```bash
dotnet ef migrations add InitialIdentity
dotnet ef database update
```

This creates all the `AspNet*` tables automatically.

---

### Step 5 — Identity Auth Controller

```csharp
// Controllers/IdentityAuthController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

[ApiController]
[Route("api/auth")]
public class IdentityAuthController : ControllerBase
{
    // UserManager: create/find/update users, check passwords
    private readonly UserManager<AppUser>  _userManager;

    // SignInManager: password sign-in with lockout support
    private readonly SignInManager<AppUser> _signInManager;

    // RoleManager: create and assign roles
    private readonly RoleManager<IdentityRole> _roleManager;

    private readonly TokenService _tokenService;

    public IdentityAuthController(
        UserManager<AppUser>    userManager,
        SignInManager<AppUser>  signInManager,
        RoleManager<IdentityRole> roleManager,
        TokenService            tokenService)
    {
        _userManager   = userManager;
        _signInManager = signInManager;
        _roleManager   = roleManager;
        _tokenService  = tokenService;
    }

    // ── Register ───────────────────────────────────────────────────────────
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        // Check if email already exists
        var existing = await _userManager.FindByEmailAsync(request.Email);
        if (existing is not null)
            return Conflict(new { message = "Email already registered" });

        var user = new AppUser
        {
            UserName  = request.Email, // Identity uses UserName for login by default
            Email     = request.Email,
            FirstName = request.FirstName,
            LastName  = request.LastName,
        };

        // CreateAsync hashes the password automatically (PBKDF2)
        var result = await _userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            // Identity returns detailed errors: password too weak, duplicate email, etc.
            var errors = result.Errors.Select(e => e.Description);
            return BadRequest(new { errors });
        }

        // Assign default role
        await EnsureRoleExistsAsync("User");
        await _userManager.AddToRoleAsync(user, "User");

        return CreatedAtAction(nameof(GetProfile), new { }, new
        {
            message = "Registration successful",
            userId  = user.Id
        });
    }

    // ── Login ──────────────────────────────────────────────────────────────
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
            return Unauthorized(new { message = "Invalid credentials" });

        // CheckPasswordSignInAsync:
        //   - verifies password hash
        //   - increments AccessFailedCount on failure
        //   - locks account after MaxFailedAccessAttempts
        var result = await _signInManager.CheckPasswordSignInAsync(
            user, request.Password, lockoutOnFailure: true);

        if (result.IsLockedOut)
            return StatusCode(423, new { message = "Account locked. Try again later." });

        if (!result.Succeeded)
            return Unauthorized(new { message = "Invalid credentials" });

        // Get all roles for this user from DB
        var roles = await _userManager.GetRolesAsync(user);

        // Get custom claims stored in AspNetUserClaims
        var customClaims = await _userManager.GetClaimsAsync(user);

        var accessToken  = _tokenService.GenerateAccessToken(user.Id, user.Email!, roles);
        var refreshToken = await _tokenService.CreateRefreshTokenAsync(
            user.Id, Request.Headers.UserAgent.ToString());

        Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
        {
            HttpOnly = true, Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires  = DateTimeOffset.UtcNow.AddDays(7)
        });

        return Ok(new { accessToken, expiresIn = 900 });
    }

    // ── Get Current User Profile ───────────────────────────────────────────
    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> GetProfile()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value!;
        var user   = await _userManager.FindByIdAsync(userId);

        if (user is null) return NotFound();

        var roles = await _userManager.GetRolesAsync(user);

        return Ok(new
        {
            user.Id,
            user.Email,
            user.FirstName,
            user.LastName,
            user.EmailConfirmed,
            user.LockoutEnd,
            roles
        });
    }

    // ── Change Password ────────────────────────────────────────────────────
    [HttpPost("change-password")]
    [Authorize]
    public async Task<IActionResult> ChangePassword(
        [FromBody] ChangePasswordRequest request)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value!;
        var user   = await _userManager.FindByIdAsync(userId);
        if (user is null) return NotFound();

        // ChangePasswordAsync verifies old password before updating
        var result = await _userManager.ChangePasswordAsync(
            user, request.CurrentPassword, request.NewPassword);

        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        // Security: invalidate all existing sessions after password change
        await _tokenService.RevokeAllUserTokensAsync(userId);

        return Ok(new { message = "Password changed. Please log in again." });
    }

    // ── Assign Role (Admin only) ───────────────────────────────────────────
    [HttpPost("assign-role")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> AssignRole([FromBody] AssignRoleRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null) return NotFound(new { message = "User not found" });

        await EnsureRoleExistsAsync(request.Role);

        if (await _userManager.IsInRoleAsync(user, request.Role))
            return Conflict(new { message = "User already has this role" });

        await _userManager.AddToRoleAsync(user, request.Role);
        return Ok(new { message = $"Role '{request.Role}' assigned to {request.Email}" });
    }

    // ── Remove Role (Admin only) ───────────────────────────────────────────
    [HttpPost("remove-role")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> RemoveRole([FromBody] AssignRoleRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null) return NotFound(new { message = "User not found" });

        var result = await _userManager.RemoveFromRoleAsync(user, request.Role);
        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        return Ok(new { message = $"Role '{request.Role}' removed from {request.Email}" });
    }

    // ── Add Custom Claim to User ───────────────────────────────────────────
    [HttpPost("add-claim")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> AddClaim([FromBody] AddClaimRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null) return NotFound();

        // Claims stored in AspNetUserClaims table
        var claim = new System.Security.Claims.Claim(request.ClaimType, request.ClaimValue);
        await _userManager.AddClaimAsync(user, claim);

        return Ok(new { message = "Claim added" });
    }

    // ── Forgot Password ────────────────────────────────────────────────────
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);

        // Always return 200 — don't reveal if email exists (security)
        if (user is null) return Ok(new { message = "If that email exists, a reset link was sent." });

        // Generate a time-limited token (uses DataProtection internally)
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);

        // TODO: send this token via email to the user
        // In production, build a URL like: https://myapp.com/reset-password?token=...&email=...
        Console.WriteLine($"Reset token for {user.Email}: {token}");

        return Ok(new { message = "If that email exists, a reset link was sent." });
    }

    // ── Reset Password ─────────────────────────────────────────────────────
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null) return BadRequest(new { message = "Invalid request" });

        // ResetPasswordAsync validates the token and updates the password hash
        var result = await _userManager.ResetPasswordAsync(
            user, request.Token, request.NewPassword);

        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        // Revoke all sessions after password reset
        await _tokenService.RevokeAllUserTokensAsync(user.Id);

        return Ok(new { message = "Password reset successful." });
    }

    // ── Seed Admin Role ────────────────────────────────────────────────────
    private async Task EnsureRoleExistsAsync(string roleName)
    {
        if (!await _roleManager.RoleExistsAsync(roleName))
            await _roleManager.CreateAsync(new IdentityRole(roleName));
    }
}

// ── Request Models ─────────────────────────────────────────────────────────
public record RegisterRequest(
    string Email, string Password,
    string? FirstName, string? LastName);

public record LoginRequest(string Email, string Password);

public record ChangePasswordRequest(
    string CurrentPassword, string NewPassword);

public record AssignRoleRequest(string Email, string Role);

public record AddClaimRequest(
    string Email, string ClaimType, string ClaimValue);

public record ForgotPasswordRequest(string Email);

public record ResetPasswordRequest(
    string Email, string Token, string NewPassword);
```

---

### Step 6 — Seed the Admin User at Startup

```csharp
// Program.cs — after building the app, before app.Run()
using (var scope = app.Services.CreateScope())
{
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

    // Create roles
    foreach (var role in new[] { "Admin", "Manager", "User" })
    {
        if (!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new IdentityRole(role));
    }

    // Create default admin
    var adminEmail = "admin@myapp.com";
    if (await userManager.FindByEmailAsync(adminEmail) is null)
    {
        var admin = new AppUser
        {
            UserName  = adminEmail,
            Email     = adminEmail,
            FirstName = "System",
            LastName  = "Admin",
            EmailConfirmed = true
        };
        await userManager.CreateAsync(admin, "Admin@Password1!");
        await userManager.AddToRoleAsync(admin, "Admin");
    }
}

app.Run();
```

---

### Identity Tables Created by EF

```
AspNetUsers          — user accounts (Id, Email, PasswordHash, LockoutEnd, ...)
AspNetRoles          — role definitions (Id, Name)
AspNetUserRoles      — which users have which roles (many-to-many)
AspNetUserClaims     — custom claims per user
AspNetRoleClaims     — custom claims per role (all users with role inherit them)
AspNetUserLogins     — external login providers (Google, etc.) linked accounts
AspNetUserTokens     — tokens issued by Identity (email confirm, password reset)
RefreshTokens        — your custom table from Section 12
```

---

### UserManager vs SignInManager — When to Use Each

| Task | Use |
|------|-----|
| Create user | `UserManager.CreateAsync` |
| Find user by email/id | `UserManager.FindByEmailAsync` |
| Check password manually | `UserManager.CheckPasswordAsync` |
| Login with lockout tracking | `SignInManager.CheckPasswordSignInAsync` |
| Add/remove role | `UserManager.AddToRoleAsync` |
| Get user's roles | `UserManager.GetRolesAsync` |
| Add/remove claim | `UserManager.AddClaimAsync` |
| Generate reset token | `UserManager.GeneratePasswordResetTokenAsync` |
| Reset password | `UserManager.ResetPasswordAsync` |
| Lock/unlock user | `UserManager.SetLockoutEndDateAsync` |
| Delete user | `UserManager.DeleteAsync` |

---

## Quick Reference Cheatsheet

| Goal | What to Use |
|------|-------------|
| Validate JWT on every request | `[Authorize]` on controller |
| Allow unauthenticated access | `[AllowAnonymous]` |
| Restrict by role | `[Authorize(Roles = "Admin")]` |
| Complex access rules | Policy + `AddPolicy()` |
| Run logic before every request | Custom Middleware |
| Run logic before a specific action | Action Filter |
| Catch exceptions in actions | Exception Filter |
| Cache or skip actions | Resource Filter |
| Wrap response format | Result Filter |
| Rate limit an endpoint | `RequireRateLimiting("policy")` |
| Validate request body | Data Annotations + `ModelState` |
| Third-party login | OAuth (`AddGoogle`, etc.) |
| Silently renew expired access token | Refresh Token rotation |
| Detect stolen refresh tokens | Family-based revocation |
| Manage users + passwords in DB | ASP.NET Core Identity |
| Auto-lock after failed logins | `SignInManager` with `lockoutOnFailure: true` |
| Password reset flow | `GeneratePasswordResetTokenAsync` + `ResetPasswordAsync` |
| Role management in DB | `UserManager.AddToRoleAsync` / `RoleManager` |
