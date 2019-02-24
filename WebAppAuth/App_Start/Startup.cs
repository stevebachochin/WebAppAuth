using System;
using System.Configuration;
using System.Threading.Tasks;
using System.Web.Http;
using WebAppAuth.Controllers;
using Microsoft.Owin;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Security.OAuth;
using Owin;

[assembly: OwinStartup(typeof(WebAppAuth.App_Start.Startup))]

namespace WebAppAuth.App_Start
{
    public class Startup
    {
        public void ConfigureAuth(IAppBuilder app)
        {
            // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=316888

            string tokenExpire = ConfigurationManager.AppSettings["tokenExpire"];
            int tokenExpireNumber = Int32.Parse(tokenExpire);

            app.UseCors(CorsOptions.AllowAll);
            var OAuthOptions = new OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(tokenExpireNumber),
                Provider = new ApplicationOAuthProvider()
            };

            app.UseOAuthBearerTokens(OAuthOptions);
            app.UseOAuthAuthorizationServer(OAuthOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());

            HttpConfiguration config = new HttpConfiguration();
            WebApiConfig.Register(config);
        }

        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
            //GlobalConfiguration.Configure(WebApiConfig.Register);

        }
    }
}
