using Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AuthDbContet>(options =>
    options.UseNpgsql(
        builder.Configuration.GetConnectionString("AuthDB")));

//Configure Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireDigit = true;

    //lockoutSettings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    //User Settigns
    options.User.RequireUniqueEmail = true;
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

    //SignIn Settings
    //options.SignIn.RequireConfirmedEmail = true;
    //options.SignIn.RequireConfirmedPhoneNumber = false;
    //options.SignIn.RequireConfirmedAccount = false;

    //Token Settings
    //options.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider;
    //options.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultEmailProvider;
    //options.Tokens.ChangeEmailTokenProvider = TokenOptions.DefaultEmailProvider;
    //options.Tokens.ChangePhoneNumberTokenProvider = TokenOptions.DefaultPhoneProvider;
    //options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;

}).AddEntityFrameworkStores<AuthDbContet>()
    .AddDefaultTokenProviders();
//// Identity's Application Cookie authenticates normal API requests.
//builder.Services.ConfigureApplicationCookie(options =>
//{
//    options.Cookie.Name = "__Host-MyApp.Auth";
//    options.Cookie.HttpOnly = true;
//    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
//    options.Cookie.SameSite = SameSiteMode.Lax;
//    options.Cookie.Path = "/";

//    options.ExpireTimeSpan = TimeSpan.FromHours(8);
//    options.SlidingExpiration = true;

//    // APIs should return 401/403, not redirect API calls to an HTML login page.
//    options.Events.OnRedirectToLogin = context =>
//    {
//        context.Response.StatusCode =
//            StatusCodes.Status401Unauthorized;
//        return Task.CompletedTask;
//    };

//    options.Events.OnRedirectToAccessDenied = context =>
//    {
//        context.Response.StatusCode =
//            StatusCodes.Status403Forbidden;
//        return Task.CompletedTask;
//    };
//});

// Google signs into Identity's temporary external cookie.
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateLifetime = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,

            ValidIssuer = builder.Configuration["JWT:issu"],
            ValidAudience = builder.Configuration["JWT:Aud"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]))
        };

    }).AddGoogleOpenIdConnect(options =>
    {
        options.ClientId = builder.Configuration["ClientId"];
        options.ClientSecret = builder.Configuration["ClientSecret"];

        options.SignInScheme = IdentityConstants.ExternalScheme;
        options.UsePkce = true;
        options.Scope.Add("email");
        options.Scope.Add("profile");
    });
    //.AddGoogle(options =>
    //{
    //    options.ClientId =
    //        builder.Configuration["ClientId"]!;

//    options.ClientSecret =
//        builder.Configuration["ClientSecret"]!;

//    options.SignInScheme = IdentityConstants.ExternalScheme;
//    options.CallbackPath = "/signin-google";

//    options.Scope.Add("email");
//    options.Scope.Add("profile");

//    options.UsePkce = true;
//});

builder.Services.AddAuthorization(options=>
{
    options.AddPolicy("RequireAdministratorRole", policy => policy.RequireRole("Admin"));
    options.AddPolicy("RequireUserRole", policy => policy.RequireRole("User"));
    //options.AddPolicy("RequireManagerRole", policy => policy.RequireRole("Manager"));
    //options.AddPolicy("RequireAdminOrManagerRole", policy => policy.RequireRole("Admin", "Manager"));
});

//builder.Services.AddAntiforgery(options =>
//{
//    options.HeaderName = "X-CSRF-TOKEN";
//    options.Cookie.Name = "__Host-MyApp.Xsrf";
//    options.Cookie.HttpOnly = true;
//    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
//    options.Cookie.SameSite = SameSiteMode.Lax;
//    options.Cookie.Path = "/";
//});

builder.Services.AddControllers();
    //(options =>
//{
//    // Automatically validates CSRF tokens on unsafe HTTP methods.
//    options.Filters.Add(
//        new Microsoft.AspNetCore.Mvc.AutoValidateAntiforgeryTokenAttribute());
//});

var frontendUrl = builder.Configuration["Frontend:BaseUrl"]
    ?? throw new InvalidOperationException(
        "Frontend:BaseUrl is missing.");

builder.Services.AddCors(options =>
{
    options.AddPolicy("Frontend", policy =>
    {
        policy
            .WithOrigins(frontendUrl)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

builder.Services.AddScoped<ITokenService, TokenService>();

var app = builder.Build();


using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
}

app.UseHttpsRedirection();

app.UseRouting();
app.UseCors("Frontend");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();