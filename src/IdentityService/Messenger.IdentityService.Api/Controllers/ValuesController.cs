using Messenger.IdentityService.Api.Contracts;
using Messenger.IdentityService.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Messenger.IdentityService.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        private readonly IUserService _userService;

        public ValuesController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("registration")]
        public async Task<IActionResult> Registration([FromQuery] RegistrationRequest request)
        {
            var result = await _userService.RegistrationAsync(request, HttpContext.Response.Cookies);
            return Ok(result);
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("login")]
        public async Task<IActionResult> Login([FromQuery] LoginRequest request)
        {
            var result = await _userService.LogInAsync(request, HttpContext.Response.Cookies);
            return Ok(result);
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("logout")]
        public async Task<IActionResult> Logout()
        {
            var token = HttpContext.Request.Cookies.FirstOrDefault(x => x.Key == "REFRESH").Value;
            await _userService.LogOutAsync(token);
            HttpContext.Response.Cookies.Delete("REFRESH");
            return Ok();
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("refresh")]
        public async Task<IActionResult> Refresh()
        {
            var token = HttpContext.Request.Cookies.FirstOrDefault(x => x.Key == "REFRESH").Value;
            var result = await _userService.RefreshTokenAsync(token);
            return Ok();
        }
    }
}
