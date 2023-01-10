using Messenger.IdentityService.Api.Contracts;
using Messenger.IdentityService.Api.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace Messenger.IdentityService.Api.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<User> _userManager;
        private readonly IJwtManager _jwtGenerator;
        private readonly JwtSecurityTokenHandler _tokenHandler;

        private readonly string _tokenName = "REFRESH";
        private readonly string _loginProvider = "Messenger.IdentityService";

        public UserService(UserManager<User> userManager, IJwtManager jwtGenerator, JwtSecurityTokenHandler tokenHandler)
        {
            _userManager = userManager;
            _jwtGenerator = jwtGenerator;
            _tokenHandler = tokenHandler;
        }

        public async Task<RegistrationResponse> RegistrationAsync(RegistrationRequest request, IResponseCookies cookies)
        {
            var condidate = await _userManager.FindByEmailAsync(request.Email);
            if (condidate != null)
                throw new Exception($"User with email address: {request.Email} already exist");

            var user = new User()
            {
                UserName = request.UserName,
                Email = request.Email
            };
            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
                throw new Exception(String.Join(",", result.Errors.Select(x => x.Description).ToArray().Select(x => x.ToString()).ToArray()));

            user = await _userManager.FindByEmailAsync(request.Email);
            var tokens = _jwtGenerator.CreateTokens(user.Email, user.Id);
            await SaveRefreshJwt(user, tokens.RefreshToken);
            CreateRefreshJwtCookie(cookies, tokens.RefreshToken);
            var retval = new RegistrationResponse(user.Id, user.UserName, user.Email, tokens.AccessToken, tokens.RefreshToken);
            return retval;
        }

        public async Task<LoginResponse> LogInAsync(LoginRequest request, IResponseCookies cookies)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
                throw new Exception($"User with email address: {request.Email} doesn't exist");

            bool isPassCorrect = await _userManager.CheckPasswordAsync(user, request.Password);
            if (!isPassCorrect)
                throw new Exception("Incorrect password");

            var tokens = _jwtGenerator.CreateTokens(user.Email, user.Id);
            await SaveRefreshJwt(user, tokens.RefreshToken);
            CreateRefreshJwtCookie(cookies, tokens.RefreshToken);
            var retval = new LoginResponse(user.Id, user.UserName, user.Email, tokens.AccessToken, tokens.RefreshToken);
            return retval;
        }

        public async Task LogOutAsync(string token)
        {
            var jwt = _tokenHandler.ReadJwtToken(token);
            var userId = jwt.Claims.SingleOrDefault(x => x.Type == JwtRegisteredClaimNames.Sub).Value;
            var user = await _userManager.FindByIdAsync(userId);
            await _userManager.RemoveAuthenticationTokenAsync(user, _loginProvider, _tokenName);
        }

        private void CreateRefreshJwtCookie(IResponseCookies cookies, string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.Now.AddHours(30d)
            };

            cookies.Append(_tokenName, token, cookieOptions);
        }

        private async Task SaveRefreshJwt(User user, string refreshToken)
        {
            var tokenData = await _userManager.GetAuthenticationTokenAsync(user, _loginProvider, _tokenName);
            if (tokenData != null)
                await _userManager.RemoveAuthenticationTokenAsync(user, _loginProvider, _tokenName);

            await _userManager.SetAuthenticationTokenAsync(user, _loginProvider, _tokenName, refreshToken);
        }
    }
}
