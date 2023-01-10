namespace Messenger.IdentityService.Api.Models
{
    public class JwtConfiguration
    {
        public string AccessKey { get; set; }
        public TimeSpan AccessLifeTime { get; set; }

        public string RefreshKey { get; set; }
        public TimeSpan RefreshLifeTime { get; set; }
    }
}
