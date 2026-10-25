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

        public AuthController(ILogger<AuthController> logger, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration config)
        {
            _logger = logger;
            _userManager = userManager;
            _signInManager = signInManager;
            _config = config;
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
                    refreshToken = refreshToken.token
                });
            }
            return BadRequest("Invalid credentials");
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto model)
        {
            var user = _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t=>t.expires > DateTime.UtcNow && t.token == model.token))?? throw new Exception("Invalid refresh token");
            if (user == null)
            {
                return BadRequest("Invalid refresh token");
            }

            var newAccessToken = GenerateJwtToken(user.Result);
            var newRefreshToken = GenerateRefreshToken();

            user.Result.RefreshTokens.RemoveAll(t => t.token == model.token);
            user.Result.RefreshTokens.Add(newRefreshToken);

            await _userManager.UpdateAsync(user.Result);

            return Ok(new
            {
                accessToken = newAccessToken,
                refreshToken = newRefreshToken.token
            });

        }

        private RefreshToken GenerateRefreshToken()
        {
            return new RefreshToken
            {
                token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                expires = DateTime.UtcNow.AddDays(7)
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


        //Google
        [HttpGet("google-login")]
        public IActionResult Login()
        {
            var callbackUrl = Url.Action(
                    nameof(GoogleResponse),
                    "Auth",
                    values: null,
                    protocol: Request.Scheme);

            var properties = new AuthenticationProperties
            {
                RedirectUri = callbackUrl
            };


            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("google-response")]
        public async Task<IActionResult> GoogleResponse()
        {
            var externalResult = await HttpContext.AuthenticateAsync
                (IdentityConstants.ExternalScheme);

            if (!externalResult.Succeeded || externalResult.Principal == null)
            {
                return BadRequest("Failed to authenticate with Google");
            }
            
            var principal = externalResult.Principal;
            var googleId = principal.FindFirstValue(ClaimTypes.NameIdentifier);

            var email = principal.FindFirstValue(ClaimTypes.Email);

            var firstName = principal.FindFirstValue(ClaimTypes.GivenName);
            var lastName = principal.FindFirstValue(ClaimTypes.Surname);

            if(string.IsNullOrWhiteSpace(googleId) || string.IsNullOrWhiteSpace(email))
            {
                return BadRequest("Invalid Google authentication data");
            }

            var user = await _userManager.FindByLoginAsync(GoogleDefaults.AuthenticationScheme,
                googleId);
            var userByEmail = await _userManager.FindByEmailAsync(email);

            if (user == null && userByEmail == null)
            {
                user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    FirstName = firstName,
                    lastName = lastName,
                    EmailConfirmed = false
                };
            }

            if (userByEmail != null && user == null)
            {
                return Conflict
                (new
                {
                    message = "A user with this email already exists. Please log in using your email and password."
                });
            }

            var createResult = await _userManager.CreateAsync(user);

            if (!createResult.Succeeded)
            {
                return BadRequest(createResult.Errors);
            }

            var roleResult = await _userManager.AddToRoleAsync(user, "User");

            if (!roleResult.Succeeded)
            {
                await _userManager.DeleteAsync(user);
                return BadRequest(roleResult.Errors);
            }

            var loginInfo = new UserLoginInfo(GoogleDefaults.AuthenticationScheme, googleId, "Google");
            var linkResult = await _userManager.AddLoginAsync(user, loginInfo); ;

            if (!linkResult.Succeeded)
            {
                await _userManager.DeleteAsync(user);
                return BadRequest(linkResult.Errors);
            }

            var accessToken = GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken();

            user.RefreshTokens.Add(refreshToken);

            var updateResult = await _userManager.UpdateAsync(user);

            if (!updateResult.Succeeded)
            {
                return StatusCode(500, new
                {
                    message = "Could not save the refresh token."
                });
            }

            // 7. امسح الـ External Cookie المؤقتة
            await HttpContext.SignOutAsync(
                IdentityConstants.ExternalScheme);

            // 8. أرجع التوكنز للعميل
            return Ok(new
            {
                accessToken,
                refreshToken = refreshToken.token
            });

        }

        // GET: /api/auth/me
        [HttpGet("me")]
        public IActionResult Me()
        {
            return Ok(new
            {
                IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
                Name = User.Identity?.Name,
                Email = User.FindFirstValue(ClaimTypes.Email),
                UserId = User.FindFirstValue(ClaimTypes.NameIdentifier)
            });
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(
                CookieAuthenticationDefaults.AuthenticationScheme);

            return Ok(new { Message = "Logged out successfully." });
        }
    }
}
