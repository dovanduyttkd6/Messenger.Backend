using Messenger.IdentityService.Api.Models;

namespace Messenger.IdentityService.Api.Services
{
    public interface IJwtManager
    {
        public JwtsModel CreateTokens(string email, string userId);
        JwtsModel RefreshToken(string token);
        bool ValidateToken(string token);
    }
}
