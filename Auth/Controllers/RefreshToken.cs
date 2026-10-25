namespace Auth.Controllers
{
    public class RefreshToken
    {
        public int id { get; set; }
        public string token { get; set; }
        public DateTime expires { get; set; }
    }
}
