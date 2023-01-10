using Messenger.IdentityService.Api.Contracts;
using Messenger.IdentityService.Api.Models;

namespace Messenger.IdentityService.Api.Services
{
    public interface IUserService
    {
        Task<RegistrationResponse> RegistrationAsync(RegistrationRequest request, IResponseCookies cookies);
        Task<LoginResponse> LogInAsync(LoginRequest request, IResponseCookies cookies);
        Task LogOutAsync(string token);
    }
}
