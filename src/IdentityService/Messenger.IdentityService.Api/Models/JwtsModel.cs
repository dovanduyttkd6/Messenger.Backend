namespace Messenger.IdentityService.Api.Models
{
    public class JwtsModel
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }

        public JwtsModel(string accessToken, string refreshToken)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;
        }
    }
}
