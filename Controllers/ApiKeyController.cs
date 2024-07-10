using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ApiKeyController : ControllerBase
    {
        [HttpGet("test")]
        [Authorize(AuthenticationSchemes = "ApiKey")]
        public IActionResult TestApiKey()
        {
            return Ok("API Key authentication successful!");
        }
    }
}
