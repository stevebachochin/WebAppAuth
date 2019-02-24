using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.DirectoryServices; //Library for AD operations
using System.DirectoryServices.AccountManagement;
using WebAppAuth.Models;
using System.Threading.Tasks;
using Microsoft.Owin.Security.OAuth;
using System.Security.Claims;
using Microsoft.Owin.Security;
using System.Web;
using Newtonsoft.Json;

namespace WebAppAuth.Controllers
{
    //public class ADController : ApiController
    public class ApplicationOAuthProvider : OAuthAuthorizationServerProvider
    {
        private DbEntities db = new DbEntities();
        ///string response = "";
        [HttpPost]
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }


        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            //build a response
            AuthResponseModel authResponse = new AuthResponseModel
            {
                Authorized = "no",
                Message = "Not Authorized",
                UserDisplayName = "",
                LoggedOn = DateTime.Now.ToString()
            };
            //tring application = context.Application;
            //GET application Field Parameter needed to do Access control / group lookup
            var data = await context.Request.ReadFormAsync();
            string application = data["application"];
            if (application == null)
            {
                //ERROR "The application type POSTED field is missing "
                authResponse.Authorized = "no";
                authResponse.Message = "Not Authorized";
                authResponse.UserDisplayName = "";

                HttpContext.Current.Response.Headers.Set("AuthResponse-Headers", JsonConvert.SerializeObject(authResponse));
                context.SetError("Invalid grant");
                return;
            }
                application = application.Trim();

            //String keywordValue = "Field Assurance";
            //Group(s) permitted to use this application(comma delimited)
            //THE USER MUST BE IN A GROUP TO USE THIS APPLICATION
            String authGroupsStr = "";
            String authGroupsAdminStr = "";
            String authGroupsITStr = "";
            String adminResponse = "no";
            String accessResponse = "no";
            String ITResponse = "no";
            //find record by keyword value
            var propertyInfo = typeof(AccessControl).GetProperty("Application");
            var result = new List <AccessControl>(
                from record in db.AccessControls.AsEnumerable().Where(a =>
                propertyInfo.GetValue(a, null).ToString().ToLower().Contains(application.ToLower())
            )
                select record

            ).AsQueryable();
            //ONLY RETURN THE FIRST VALUE IN THE RESULT LIST (IN CASE THERE HAPPENS TO BE TWO OF THE SAME RECORD
            if (result == null || result.FirstOrDefault() == null)
            {
                authResponse.Authorized = "no";
                authResponse.Message = "Not Authorized";
                authResponse.UserDisplayName = "";

                HttpContext.Current.Response.Headers.Set("AuthResponse-Headers", JsonConvert.SerializeObject(authResponse));
                context.SetError("Unable to find keyword record");
                return;
            }

    
            //get first record result.First()
            authGroupsStr = result.First().Groups.ToString();
            authGroupsAdminStr = result.First().GroupsAdmin.ToString();
            authGroupsITStr = result.First().GroupsIT.ToString();
            //authGroupsStr = "Steve";

            //Convert comma seperated string of Groups in to an array
            String[] authGroups = authGroupsStr.Split(',');
            String[] authGroupsAdmin = authGroupsAdminStr.Split(',');
            String[] authGroupsIT = authGroupsITStr.Split(',');
            String username = context.UserName;
            String password = context.Password;

            if (username == "" || password == "")
            {
                authResponse.Authorized = "no";
                authResponse.Message = "Invalid Credentials";
                authResponse.UserDisplayName = "";

                HttpContext.Current.Response.Headers.Set("AuthResponse-Headers", JsonConvert.SerializeObject(authResponse));
                context.SetError("Invalid Credentialsg");
            }

            username = username.Trim();
            password = password.Trim();

            //STEP 1: Validate Credentials
            bool isValid = false;
            using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, "cryolife"))
            {
                isValid = pc.ValidateCredentials(username, password, ContextOptions.Negotiate);


                if (!isValid)
                {
                    //Invalid login using stand SamAccountName. Check is user used there FULL NAME 
                    UserPrincipal user = UserPrincipal.FindByIdentity(pc, IdentityType.Name, username);
                    if (user == null)
                    {
                        //Full name not found in AD ... so invalid username / password
                        authResponse.Authorized = "no";
                        authResponse.Message = "Invalid username or password";
                        authResponse.UserDisplayName = "";
                        HttpContext.Current.Response.Headers.Set("AuthResponse-Headers", JsonConvert.SerializeObject(authResponse));
                        context.Validated(identity);
                        return;
                    }
                    else
                    {
                        //UserName was found in AD.  Convert to SamAccount name ... use that to Validate credentials
                        username = user.SamAccountName;

                        isValid = pc.ValidateCredentials(username, password, ContextOptions.Negotiate);
                        if (!isValid)
                        {
                            //Second attempt to Validate user Failed.
                            authResponse.Authorized = "no";
                            authResponse.Message = "Invalid username or password";
                            authResponse.UserDisplayName = username + " " + password;
                            HttpContext.Current.Response.Headers.Set("AuthResponse-Headers", JsonConvert.SerializeObject(authResponse));
                            context.Validated(identity);
                            return;
                        }
                        //user is valididated "Common User Name" converted to SamAccountName.
                    }
                }
                //STEP 2: GET USER GROUPS (REQUIRED FOR THIS APP)
                //every "username is now Validated (correct username and password)

                if (username.Contains("@"))
                {
                    int idx = username.IndexOf("@");
                    username = username.Substring(0, idx);
                }

                //RUN ALL SUCCESS THROUGH ONE FINAL CHECK TO SEE IF THEY ARE IN AD
                UserPrincipal user2 = UserPrincipal.FindByIdentity(pc, IdentityType.SamAccountName, username);
                if (user2 == null)
                {
                    //User doesn't exist//SECOND TEST SHOULD WORK BUT...User should be found in AD
                    authResponse.Authorized = "no";
                    authResponse.Message = "Invalid Credentials";
                    authResponse.UserDisplayName = username;
                    HttpContext.Current.Response.Headers.Set("AuthResponse-Headers", JsonConvert.SerializeObject(authResponse));
                    context.Validated(identity);
                    return;
                }
                else
                {
                    if (authGroupsStr.ToLower() == "all")
                    {
                        accessResponse = "yes";
                    }
                    string samAccountName = user2.SamAccountName;
                    string emailAddress = user2.EmailAddress;
                    var groups = user2.GetGroups();
                    var userDisplayName = user2.DisplayName;
                    var groupStr = "";
                    using (groups)
                    {
                        foreach (Principal group in groups) // cycle through all the groups for this user
                        {
                            Console.WriteLine(group.SamAccountName);
                            //check each group user is in againt Authorized Groups in AuthGroupsStr variable
                            //convert to lower case
                            groupStr = group.SamAccountName.ToLower();

                            //GENERAL ACCESS TO THE APPLICATION
                            foreach (String authGroup in authGroups)
                            {
                                if (groupStr.Contains(authGroup.Trim().ToLower()))
                                {
                                    accessResponse = "yes";
                                }
                            }
                                    
                            //CHECK IF ADMIN
                            foreach (String authGroupAdmin in authGroupsAdmin)
                            {
                                if (groupStr.Contains(authGroupAdmin.Trim().ToLower()))
                                {
                                    adminResponse = "yes";
                                    accessResponse = "yes";
                                }
                            }

                            //CHECK IF IT
                            foreach (String authGroupIT in authGroupsIT)
                            {
                                if (groupStr.Contains(authGroupIT.Trim().ToLower()))
                                {
                                    ITResponse = "yes";
                                    accessResponse = "yes";
                                }
                            }
                        }

                    } // end using (groups)
                    if (accessResponse == "yes")
                    {
                        //context.SetError("BIG ERROR"+emailAddress);
                        //return;
                        //Group matched ... user is authorized.
                        authResponse.Authorized = "yes";
                        authResponse.Message = "Authorized";
                        authResponse.Admin = adminResponse;
                        authResponse.IT = ITResponse;
                        authResponse.Application = application;
                        authResponse.UserDisplayName = userDisplayName;
                        authResponse.UserEmailAddress = emailAddress;
                        HttpContext.Current.Response.Headers.Set("AuthResponse-Headers", JsonConvert.SerializeObject(authResponse));
                        identity.AddClaim(new Claim("Authorized", "yes"));
                        identity.AddClaim(new Claim("Admin", adminResponse));
                        identity.AddClaim(new Claim("IT", ITResponse));
                        identity.AddClaim(new Claim("Message", "Authorized"));
                        identity.AddClaim(new Claim("UserDisplayName", userDisplayName));
                        identity.AddClaim(new Claim("LoggedOn", DateTime.Now.ToString()));
                        identity.AddClaim(new Claim("Application", application));
                        identity.AddClaim(new Claim("UserEmailAddress", emailAddress));
                        context.Validated(identity);
                        return;
                    }


                    //USER IS IN NON OF THE AUTHORIZED GROUPS.
                    context.SetError("Not Authorized");
                    return;
                }
    

            }
       
        }
    }
}
