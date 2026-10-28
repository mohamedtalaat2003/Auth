using Google.Apis.Auth.AspNetCore3;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ILogger<AuthController> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _config;
        private readonly IAntiforgery _antiforgery;
        private readonly ITokenService _tokenService;

        private const string GoogleBindingCookie = "_Host-GoogleLogin";
        private readonly AuthDbContet _db;


        public AuthController(ILogger<AuthController> logger, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager,
            IConfiguration config, IAntiforgery antiforgery,
            AuthDbContet db, ITokenService tokenService)
        {
            _logger = logger;
            _userManager = userManager;
            _signInManager = signInManager;
            _config = config;
            _antiforgery = antiforgery;
            _db = db;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                FirstName = model.FirstName,
                lastName = model.lastName
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                // Assign default role
                await _userManager.AddToRoleAsync(user, "User");
                return Ok(new { message = "Registration successful" });
            }
            return BadRequest(result.Errors);

        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
            {
                return BadRequest(new { message = "Invalid email or password" });
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: false);

            if (result.Succeeded)
            {
                // Generate both tokens
                var accessToken = GenerateJwtToken(user);
                var refreshToken = GenerateRefreshToken();
                // Save refresh token to user
                user.RefreshTokens.Add(refreshToken);
                await _userManager.UpdateAsync(user);
                return Ok(new
                {
                    accessToken = accessToken,
                    refreshToken = refreshToken.TokenHash
                });
            }
            return BadRequest("Invalid credentials");
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto model)
        {
            var user = _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.ExpiresAtUtc > DateTime.UtcNow && t.TokenHash == model.token)) ?? throw new Exception("Invalid refresh token");
            if (user == null)
            {
                return BadRequest("Invalid refresh token");
            }

            var newAccessToken = GenerateJwtToken(user.Result);
            var newRefreshToken = GenerateRefreshToken();

            user.Result.RefreshTokens.RemoveAll(t => t.TokenHash == model.token);
            user.Result.RefreshTokens.Add(newRefreshToken);

            await _userManager.UpdateAsync(user.Result);

            return Ok(new
            {
                accessToken = newAccessToken,
                refreshToken = newRefreshToken.TokenHash
            });

        }

        private RefreshToken GenerateRefreshToken()
        {
            return new RefreshToken
            {
                TokenHash = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
            };
        }

        private string GenerateJwtToken(ApplicationUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),

                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Key"] ?? throw new ArgumentNullException("JWT:Key")));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var token = new JwtSecurityToken(
                issuer: _config["JWT:Issuer"],
                audience: _config["JWT:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        ////Google
        //[HttpGet("csrf")]
        //[AllowAnonymous]
        //public IActionResult GetCsrfToken()
        //{
        //    var tokens = _antiforgery.GetAndStoreTokens(HttpContext);

        //    return Ok(new
        //    {
        //        token = tokens.RequestToken
        //    });
        //}

        // 2. Start Google authentication.
        [HttpGet("google-login")]
        [AllowAnonymous]
        public IActionResult GoogleLogin()
        {
            var browserbinding = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

            Response.Cookies.Append(
               GoogleBindingCookie,
               browserbinding,
               new CookieOptions
               {
                   HttpOnly = true,
                   Secure = true,
                   SameSite = SameSiteMode.Lax,
                   Path = "/",
                   MaxAge = TimeSpan.FromMinutes(5),
                   IsEssential = true
               });

            var callbackUrl = Url.Action(
                nameof(GoogleCallback),
                "Auth",
                values: null,   
                protocol: Request.Scheme);

            var properties =
                _signInManager.ConfigureExternalAuthenticationProperties(
                    GoogleDefaults.AuthenticationScheme,
                    callbackUrl!);

            return Challenge(properties, GoogleOpenIdConnectDefaults.AuthenticationScheme);
        }

        // 3. Google middleware handles /signin-google first.
        // It then redirects here with the temporary external identity.
        [HttpGet("google-callback")]
        [AllowAnonymous]
        public async Task<IActionResult> GoogleCallback()
        {
            if(!Request.Cookies.TryGetValue(GoogleBindingCookie, out var browserBinding))
            {
                return Unauthorized();
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();

            if (info is null)
                return Unauthorized("Google authentication failed.");

            // Check whether this Google account is already linked.
            var user = await _userManager.FindByLoginAsync(
                info.LoginProvider,
                info.ProviderKey);

            if (user is null)
            {
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);

                if (string.IsNullOrWhiteSpace(email))
                    return BadRequest("Google email was not provided.");

                // Don't automatically link an existing account by email alone.
                var existingUser = await _userManager.FindByEmailAsync(email);

                if (existingUser is not null)
                    return Conflict("This email already exists. Sign in and link Google.");

                user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    EmailConfirmed = false,
                    FirstName = info.Principal.FindFirstValue(ClaimTypes.GivenName) ?? "",
                    lastName = info.Principal.FindFirstValue(ClaimTypes.Surname) ?? ""
                };

                var createUser = await _userManager.CreateAsync(user);

                if (!createUser.Succeeded)
                    return BadRequest(createUser.Errors);

                var roleResult = await _userManager.AddToRoleAsync(user, "User");

                if (!roleResult.Succeeded)
                    return BadRequest(roleResult.Errors);

                var loginResult = await _userManager.AddLoginAsync(user, info);

                if (!loginResult.Succeeded)
                {
                    await _userManager.DeleteAsync(user);
                    return BadRequest(loginResult.Errors);
                }
            }

            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            var rowCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(34));

            var codeHash = _tokenService.HashToken(rowCode);
            var bindingHash = _tokenService.HashToken(browserBinding);

            await _db.externalLoginCodes.AddAsync
                (new ExternalLoginCode
                {
                    CodeHash = codeHash,
                    BrowserBindingHash = bindingHash,
                    UserId = user.Id,
                    ExpiresUtc = DateTime.UtcNow.AddMinutes(1)
                });
            await _db.SaveChangesAsync();

            var frontendUrl = _config["Frontend:BaseUrl"]
        ?? throw new InvalidOperationException(
            "Frontend:BaseUrl is missing.");

            return Redirect(
                $"{frontendUrl}/auth/callback?code={Uri.EscapeDataString(rowCode)}");
        }

        // 4. The SPA can check whether the user is signed in.
        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> Me()
        {
            var user = await _userManager.GetUserAsync(User);

            if (user is null)
                return Unauthorized();

            return Ok(new
            {
                user.Id,
                user.Email,
                user.UserName,
                user.FirstName,
                user.lastName
            });
        }

        // 5. Sign out of the application.
        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();

            return NoContent();
        }


        public sealed record ExchangeCodeRequest(string Code);

        public async Task<IActionResult> ExchangeCode([FromBody] ExchangeCodeRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Code))
                return BadRequest();


            if (!Request.Cookies.TryGetValue(
                    GoogleBindingCookie, out var browserBinding))
            {
                return Unauthorized();
            }

            var codeHash = TokenService.HashToken(request.Code);
            var bindingHash = TokenService.HashToken(browserBinding);
            var now = DateTime.UtcNow;

            var code = await _db.externalLoginCodes
          .SingleOrDefaultAsync(x =>
              x.CodeHash == codeHash &&
              x.BrowserBindingHash == bindingHash &&
              x.UsedAtUtc == null &&
              x.ExpiresUtc > now);

            if (code is null)
                return Unauthorized();

            var consumed = await _db.ExternalLoginCodes
       .Where(x =>
           x.Id == code.Id &&
           x.UsedAtUtc == null &&
           x.ExpiresAtUtc > now &&
           x.BrowserBindingHash == bindingHash)
       .ExecuteUpdateAsync(setters =>
           setters.SetProperty(x => x.UsedAtUtc, now));

            if (consumed > 1)
                return Unauthorized();
            var user = await _userManager.FindByIdAsync(code.UserId);

            if (user is null)
                return Unauthorized();

            var accessToken =
                await _tokenService.CreateAccessTokenAsync(user);

            var rawRefreshToken = TokenService.CreateRefreshToken();

            var refreshEntity = _tokenService.CreateRefreshTokenEntity(
                user, rawRefreshToken);

            _db.RefreshTokens.Add(refreshEntity);
            await _db.SaveChangesAsync();

            return Ok(new
            {
                accessToken,
                expiresIn = 900,
                refreshToken = rawRefreshToken
            });

        }
    }
}
