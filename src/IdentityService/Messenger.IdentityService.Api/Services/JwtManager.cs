using Messenger.IdentityService.Api.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Messenger.IdentityService.Api.Services
{
    public class JwtManager : IJwtManager
    {
        private readonly JwtSecurityTokenHandler _tokenHandler;
        private readonly JwtConfiguration _jwtConfiguration;

        private readonly SigningCredentials _accessCredentials;
        private readonly SigningCredentials _refreshCredentials;

        private readonly TokenValidationParameters _tokenValidationParameters;

        public JwtManager(JwtSecurityTokenHandler tokenHandler, JwtConfiguration jwtConfiguration, TokenValidationParameters tokenValidationParameters)
        {
            _tokenHandler = tokenHandler;
            _jwtConfiguration = jwtConfiguration;

            var accessSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfiguration.AccessKey));
            _accessCredentials = new SigningCredentials(accessSecurityKey, SecurityAlgorithms.HmacSha512Signature);

            var refreshSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfiguration.RefreshKey));
            _refreshCredentials = new SigningCredentials(refreshSecurityKey, SecurityAlgorithms.HmacSha512Signature);

            _tokenValidationParameters = tokenValidationParameters;
        }

        public JwtsModel CreateTokens(string email, string userId)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Email, email),
                new Claim(JwtRegisteredClaimNames.Sub, userId)
            };

            var accessTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.Add(_jwtConfiguration.AccessLifeTime),
                SigningCredentials = _accessCredentials
            };

            var refreshTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.Add(_jwtConfiguration.RefreshLifeTime),
                SigningCredentials = _refreshCredentials
            };

            var accessToken = _tokenHandler.CreateToken(accessTokenDescriptor);
            var refreshToken = _tokenHandler.CreateToken(refreshTokenDescriptor);
            var tokens = new JwtsModel(_tokenHandler.WriteToken(accessToken), _tokenHandler.WriteToken(refreshToken));

            return tokens;
        }

        public JwtsModel RefreshToken(string token)
        {
            if (token == null)
                throw new Exception($"Unautharized");
            bool isValid = ValidateToken(token);
            var tokenData = await _userManager.GetAuthenticationTokenAsync(user, "Messenger.IdentityService", "REFRESH");

        }

        public bool ValidateToken(string token)
        {
            //var _tokenValidationParameters = new TokenValidationParameters()
            //{
            //    ValidateLifetime = false, // Because there is no expiration in the generated token
            //    ValidateAudience = false, // Because there is no audiance in the generated token
            //    ValidateIssuer = false,   // Because there is no issuer in the generated token
            //    ValidIssuer = "Sample",
            //    ValidAudience = "Sample",
            //    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfiguration.RefreshKey))
            //};

            try
            {
                _tokenHandler.ValidateToken(token, _tokenValidationParameters, out _);
            }
            catch
            {
                return false;
            }

            return true;
        }
    }
}
