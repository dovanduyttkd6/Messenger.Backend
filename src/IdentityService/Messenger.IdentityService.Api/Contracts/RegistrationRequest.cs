namespace Messenger.IdentityService.Api.Contracts
{
    public class RegistrationRequest
    {
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
