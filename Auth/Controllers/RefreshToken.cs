namespace Auth.Controllers
{
    public class RefreshToken
    {
        public Guid Id { get; set; }
        public string TokenHash { get; set; }
        public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresAtUtc { get; set; }
        public DateTime RevocedAtUtc { get; set; }
        public string UserId { get; set; }
        public Guid? ReplacedByTokenId { get; set; }
        public ApplicationUser User { get; set; }
    }
}
