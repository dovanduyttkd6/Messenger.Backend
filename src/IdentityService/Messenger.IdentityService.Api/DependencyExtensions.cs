using Messenger.IdentityService.Api.Models;
using Messenger.IdentityService.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace Messenger.IdentityService.Api
{
    public static class DependencyExtensions
    {
        public static IServiceCollection AddIdentityDatabase(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContextPool<IdentityDbContext>(options =>
                options.UseNpgsql(
                    configuration.GetConnectionString("IdentityDbConnection")
                )
            );

            services.AddIdentityCore<User>(x =>
            {
                x.Password.RequireDigit = false;
                x.Password.RequireLowercase = false;
                x.Password.RequireUppercase = false;
                x.Password.RequireNonAlphanumeric = false;
                x.User.RequireUniqueEmail = true;
                x.User.AllowedUserNameCharacters = null;
            }).AddRoles<IdentityRole>()
            .AddSignInManager()
            .AddDefaultTokenProviders()
            .AddEntityFrameworkStores<IdentityDbContext>();

            return services;
        }

        public static IServiceCollection AddServices(this IServiceCollection services)
        {
            services.AddScoped<IUserService, UserService>();

            return services;
        }

        public static IServiceCollection AddJwtServices(this IServiceCollection services, IConfiguration configuration)
        {
            var jwtConfiguration = configuration.GetSection(nameof(JwtConfiguration)).Get<JwtConfiguration>();
            services.AddSingleton(jwtConfiguration);
            services.AddSingleton<JwtSecurityTokenHandler>();
            services.AddScoped<IJwtManager, JwtManager>();

            services.AddAuthentication(authenticationOptions =>
            {
                authenticationOptions.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                authenticationOptions.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(bearerOptions =>
            {
                bearerOptions.RequireHttpsMetadata = false;
                bearerOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    LogValidationExceptions = true, //default
                    RequireExpirationTime = true, //default
                    RequireSignedTokens = false, //default = true
                    RequireAudience = true, //default
                    SaveSigninToken = false, //default
                    TryAllIssuerSigningKeys = true, //default important
                    ValidateActor = false, //default = true
                    ValidateAudience = false, //default true
                    ValidateIssuer = false, //default true
                    ValidateIssuerSigningKey = false, //default
                    ValidateLifetime = true, //default
                    ValidateTokenReplay = false, //default
                    IssuerSigningKeys = new SecurityKey[]
                    {
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfiguration.AccessKey)),
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfiguration.RefreshKey))
                    },

                    //SignatureValidator = (token, _) =>
                    //    new JwtSecurityToken(token),
                };

                bearerOptions.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                            context.Response.Headers.Add("Token-Expired", "true");

                        return Task.CompletedTask;
                    }
                };
            });
            return services;
        }

        public static IServiceCollection ConfigureAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            //var jwtConfig = configuration.GetSection(nameof(JwtConfiguration)).Get<JwtConfiguration>();

            //services.ConfigureJwtAuthService(jwtConfig);

            //services.AddSingleton<JwtSecurityTokenHandler>();

            //var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig.Key));
            //var tokenValidationParameters = new TokenValidationParameters
            //{
            //    ValidateIssuerSigningKey = true,
            //    IssuerSigningKey = key,
            //    ValidateAudience = false,
            //    ValidateIssuer = false,
            //    ClockSkew = TimeSpan.Zero
            //};
            
            //services.AddSingleton(tokenValidationParameters);
            
            //services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            //    .AddJwtBearer(
            //        opt =>
            //        {
            //            opt.TokenValidationParameters = tokenValidationParameters;

            //            opt.Events = new JwtBearerEvents
            //            {
            //                OnAuthenticationFailed = context =>
            //                {
            //                    if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
            //                        context.Response.Headers.Add("Token-Expired", "true");

            //                    return Task.CompletedTask;
            //                }
            //            };
            //        });

            return services;
        }

        public static IServiceCollection ConfigureJwtAuthentication(this IServiceCollection services,
            IConfiguration configuration)
        {
            services.AddSingleton<JwtSecurityTokenHandler>();

            services.AddAuthentication(authenticationOptions =>
            {
                authenticationOptions.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                authenticationOptions.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(bearerOptions =>
            {
                bearerOptions.RequireHttpsMetadata = false;
                bearerOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    LogValidationExceptions = true, //default
                    RequireExpirationTime = true, //default
                    RequireSignedTokens = false, //default = true
                    RequireAudience = true, //default
                    SaveSigninToken = false, //default
                    TryAllIssuerSigningKeys = true, //default important
                    ValidateActor = false, //default = true
                    ValidateAudience = false, //default true
                    ValidateIssuer = false, //default true
                    ValidateIssuerSigningKey = false, //default
                    ValidateLifetime = true, //default
                    ValidateTokenReplay = false, //default
                    IssuerSigningKeys = new SecurityKey[]
                    {
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfiguration.AccessKey)),
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfiguration.RefreshKey))
                    },

                    //SignatureValidator = (token, _) =>
                    //    new JwtSecurityToken(token),
                };

                bearerOptions.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                            context.Response.Headers.Add("Token-Expired", "true");

                        return Task.CompletedTask;
                    }
                };
            });

            return services;
        }
    }
}