using Auth.Controllers;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Auth
{
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _config;
        private readonly UserManager<ApplicationUser> _userManager;

        public TokenService(IConfiguration config, UserManager<ApplicationUser> userManager)
        {
            _config = config;
            _userManager = userManager;
        }
        public async Task<string> CreateAccessToken(ApplicationUser user)
        {
            var key = _config["JWT:Key"] ??
                throw new InvalidOperationException("JWT Key missed");

            var issuer = _config["JWT:issu"] ??
                throw new InvalidOperationException("JWT Issuer Missed");

            var audience = _config["JWT:Aud"] ??
                throw new InvalidOperationException("JWT Audience Missed");

            var claims = new List<Claim>
            {
                new (JwtRegisteredClaimNames.Sub, user.Id),
                new (JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new (JwtRegisteredClaimNames.Email,user.Email??string.Empty)
            };

            var role = await _userManager.GetRolesAsync(user);

            claims.AddRange(role.Select(role => new Claim(ClaimTypes.Role, role)));

            var signKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));

            var credentials = new SigningCredentials(signKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken
            (
                issuer: issuer,
                audience: audience,
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddMinutes(35),
                signingCredentials:credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string CreateRefreshToken()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        }
        public string HashToken(string token)
        {
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
        }

        public RefreshToken CreateRefreshTokenEntity(ApplicationUser user, string token)
        {
            return new RefreshToken
            {
                UserId = user.Id,
                TokenHash = HashToken(token),
                ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
            };
        }

    }
}
