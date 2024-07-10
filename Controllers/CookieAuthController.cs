using System.Security.Claims;
using AuthTest.RequestModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CookieAuthController(IConfiguration configuration) : ControllerBase
    {
        [HttpGet("test")]
        [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
        public IActionResult TestCookieAuth()
        {
            return Ok("Cookie-based authentication successful!");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest login)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("Model is invalid.");
            }

            if (login.Username != configuration["BasicAuth:Username"] || login.Password != configuration["BasicAuth:Password"])
            {
                return Unauthorized("Email or password are wrong.");
            }

            List<Claim> claims = [new(ClaimTypes.Name, login.Username)];

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var authProperties = new AuthenticationProperties
            {
                IsPersistent = true, // Set to true for persistent cookies
                ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30) // Cookie expiration
            };

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);

            return Ok("Login successful");
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(
                CookieAuthenticationDefaults.AuthenticationScheme);

            return Ok("User has been logged out");
        }
    }
}
