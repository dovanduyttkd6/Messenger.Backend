namespace Messenger.IdentityService.Api.Contracts
{
    public class RegistrationResponse
    {
        public string UserId { get; set; }
        public string UserName { get; set; }
        public string UserEmail { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }

        public RegistrationResponse(string userId, string userName, string userEmail, string accessToken, string refreshToken)
        {
            UserId = userId;
            UserName = userName;
            UserEmail = userEmail;
            AccessToken = accessToken;
            RefreshToken = refreshToken;
        }
    }
}
