namespace Auth.Controllers
{
    public class ExternalLoginCode
    {
        public Guid Id { get; set; }
        public string CodeHash { get; set; } = null;
        public string UserId { get; set; } 
        public string BrowserBindingHash { get; set; }
        public DateTime ExpiresUtc { get; set; }
        public DateTime UsedAtUtc { get; set; }
        public ApplicationUser User { get; set; }
    }
}
