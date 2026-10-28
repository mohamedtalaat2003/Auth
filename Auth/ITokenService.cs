using Auth.Controllers;
using System.Security.Cryptography;

namespace Auth
{
    public interface ITokenService
    {
        public Task<string> CreateAccessToken(ApplicationUser user);
        public string CreateRefreshToken();
        public string HashToken(string token);
        public Task<RefreshToken> CreateRefreshTokenEntity(ApplicationUser user, string token);
    }
}
