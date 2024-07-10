using AuthTest.RequestModels;
using AuthTest.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthTest.Controllers
{
    [Route("api/[controller]")]
    public class JwtAuthController(JwtTokenGenerator tokenGenerator) : ControllerBase
    {
        [HttpGet("test")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public IActionResult TestJwtAuth()
        {
            return Ok("JWT authentication successful!");
        }

        [HttpPost("token")]
        public IActionResult GenerateToken([FromBody] LoginRequest loginRequest)
        {
            if (!ModelState.IsValid) return BadRequest("Model state is not valid.");

            var token = tokenGenerator.GenerateToken(loginRequest.Username, loginRequest.Password);

            if (token == null) return BadRequest("Wrong username or password");

            return Ok(new { token });
        }
    }
}
