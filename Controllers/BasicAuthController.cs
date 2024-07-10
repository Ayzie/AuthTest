using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class BasicAuthController : ControllerBase
    {
        [HttpGet("test")]
        [Authorize(AuthenticationSchemes = "Basic")]
        public IActionResult TestBasicAuth()
        {
            return Ok("Basic authentication successful!");
        }
    }
}
