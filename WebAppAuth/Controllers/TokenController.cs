using System.Security.Claims;
using System.Web.Http;
using WebAppAuth.Models;

namespace WebAppAuth.Controllers
{
    public class TokenController : ApiController
    {
        [HttpGet]
        [Route("api/Token")]
        [Authorize]

        public AuthResponseModel GetUserClaims()
        {
            var identityClaims = User.Identity as ClaimsIdentity;
            AuthResponseModel authResponse = new AuthResponseModel
            {
                Authorized = identityClaims.FindFirst("Authorized")?.Value,
                Message = identityClaims.FindFirst("Message")?.Value,
                UserDisplayName = identityClaims.FindFirst("UserDisplayName")?.Value,
                LoggedOn = identityClaims.FindFirst("LoggedOn")?.Value,
                Admin = identityClaims.FindFirst("Admin")?.Value,
                IT = identityClaims.FindFirst("IT")?.Value,
                Application = identityClaims.FindFirst("Application")?.Value,
                UserEmailAddress = identityClaims.FindFirst("UserEmailAddress")?.Value,
            };
            return authResponse;
        }


    }
}
