using Microsoft.Owin.Extensions;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace WindowsAuthAppToAADDemo
{
	public partial class Startup
	{
		private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
		private static string aadInstance = EnsureTrailingSlash(ConfigurationManager.AppSettings["ida:AADInstance"]);
		private static string tenantId = ConfigurationManager.AppSettings["ida:TenantId"];
		private static string postLogoutRedirectUri = ConfigurationManager.AppSettings["ida:PostLogoutRedirectUri"];

		string authority = aadInstance + tenantId;

		public void ConfigureAuth(IAppBuilder app)
		{
			app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

			app.UseCookieAuthentication(new CookieAuthenticationOptions());

			app.UseOpenIdConnectAuthentication(
			new OpenIdConnectAuthenticationOptions
			{
				ClientId = clientId,
				Authority = authority,
				PostLogoutRedirectUri = postLogoutRedirectUri,

				Notifications = new OpenIdConnectAuthenticationNotifications()
				{
					AuthenticationFailed = (context) =>
					{
						return System.Threading.Tasks.Task.FromResult(0);
					},
					SecurityTokenValidated = (context) =>
					{
						var claims = context.AuthenticationTicket.Identity.Claims;
						var groups = from c in claims
									 where c.Type == "groups"
									 select c;

						foreach (var group in groups)
						{
							context.AuthenticationTicket.Identity.AddClaim(new Claim(ClaimTypes.Role, group.Value));
						}
						return Task.FromResult(0);
					}
				}

			}
			);

			// This makes any middleware defined above this line run before the Authorization rule is applied in web.config
			app.UseStageMarker(PipelineStage.Authenticate);
		}

		private static string EnsureTrailingSlash(string value)
		{
			if (value == null)
			{
				value = string.Empty;
			}

			if (!value.EndsWith("/", StringComparison.Ordinal))
			{
				return value + "/";
			}

			return value;
		}
	}
}
