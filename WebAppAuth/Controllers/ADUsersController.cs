using System.Web.Http;
using System.Threading.Tasks;
using System.DirectoryServices.AccountManagement;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.DirectoryServices;

namespace WebAppAuth.Controllers
{
    public class ADUsersController : ApiController
    {
        List<ADUser> userNames = new List<ADUser>();

        [HttpPost]
        [Route("api/Users")]

        public IHttpActionResult GetUsers(HttpRequestMessage request)
        {
            IEnumerable<string> headerValues = request.Headers.GetValues("App");
            var id = headerValues.FirstOrDefault();
            int cnt = 0;
            if (id == "CryoLife App")
            {

            var context = new PrincipalContext(ContextType.Domain, "cryolife.com");
            UserPrincipal qbeUser = new UserPrincipal(context);
                qbeUser.Enabled = true; //only enabled users
                // qbeUser.PasswordNeverExpires = false; //not ALWAYS service accounts !!
                //qbeUser.GivenName = "Steve";
                PrincipalSearcher srch = new PrincipalSearcher(qbeUser);
                //IMPORTANT
                // set the PageSize on the underlying DirectorySearcher to get all entries
                ((DirectorySearcher)srch.GetUnderlyingSearcher()).PageSize = 500;

                foreach (UserPrincipal result in srch.FindAll())
                {

                    if (
                        result != null && 
                        result.DisplayName != null && 
                        result.EmailAddress != null && 
                        result.GivenName != null &&
                        result.GivenName != result.DisplayName
                        )
                    {
                        cnt++;
                        userNames.Add(
                            new ADUser()
                            {
                                ADFullName = result.Name,
                                ADEmailAddress = result.EmailAddress
                            }
                            );
                    }
                }
            //SORT THIS INFORMATION
            List<ADUser> SortedList = userNames.OrderBy(o => o.ADFullName).ToList();

                return Ok(SortedList);

            }

            return NotFound();
        }
    }
}
