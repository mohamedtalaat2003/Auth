using System.Security.Cryptography;

namespace Auth
{
    public interface ITokenService
    {
        public string CreateAccessToken(ApplicationUser user);
        public string CreateRefreshToken();
        public string HashToken(string token);
        public string CreateRefreshTokenEntity(ApplicationUser user, string token);
    }
}
