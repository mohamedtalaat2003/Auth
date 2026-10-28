using Auth.Controllers;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileSystemGlobbing.Internal;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics.Metrics;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.Intrinsics.X86;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Auth
{
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _config;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContet _db;

        public TokenService(IConfiguration config, UserManager<ApplicationUser> userManager,AuthDbContet db)
        {
            _config = config;
            _userManager = userManager;
            _db = db;
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
            if (token is null)
                throw new InvalidOperationException("token not found use result pattern better than throw exception");

            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
        }

        public async Task<RefreshToken> CreateRefreshTokenEntity(ApplicationUser user, string token)
        {
            var exisitingUser = await _db.Users.SingleOrDefaultAsync(x => x.Id == user.Id);

            if (exisitingUser is null)
                throw new InvalidOperationException("user not found use result pattern better than throw exception");

            if(token is null)
                throw new InvalidOperationException("token not found use result pattern better than throw exception");

            //var tokenExisting = await _db.RefreshTokens.SingleOrDefaultAsync(x => x.UserId == user.Id && x.TokenHash == token);

            ////if(DateTime.UtcNow < tokenExisting.ExpiresAtUtc && tokenExisting is not null)
            ////    return 


            
            return new RefreshToken
            {
                UserId = user.Id,
                TokenHash = HashToken(token),
                ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
            };
        }

    }
}
