using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using JWT_Example.Security;

namespace JWT_Example
{
    public class Startup
    {

        public IConfiguration Configuration { get; set; }

        //private const string ISSUER = "c1f51f42";
        //private const string AUDIENCE = "c6bbbb645024";
        //private const string SECRET_KEY = "c1f51f42-5727-4d15-b787-c6bbbb645024";
        //private readonly SymmetricSecurityKey _signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(SECRET_KEY));

        private TokenOptions _options = new TokenOptions();

        public Startup(IHostingEnvironment env)
        {
            var configurationBuilder = new ConfigurationBuilder()
               .SetBasePath(env.ContentRootPath)
               .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
               .AddEnvironmentVariables();

            Configuration = configurationBuilder.Build();
        }

        public void ConfigureServices(IServiceCollection services)
        {
       		services.AddMvc(config =>
			{
				var policy = new AuthorizationPolicyBuilder()
								 .RequireAuthenticatedUser()
								 .Build();
				config.Filters.Add(new AuthorizeFilter(policy));
			});
       
            services.AddCors();

			services.AddAuthorization(options =>
			{
				options.AddPolicy("User", policy => policy.RequireClaim("JWT_Example", "User"));
				options.AddPolicy("Admin", policy => policy.RequireClaim("JWT_Example", "Admin"));
			});

			//services.Configure<TokenOptions>(options =>
			//{
			//	options.Issuer = ISSUER;
			//	options.Audience = AUDIENCE;
			//	options.SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256);
			//});

			services.Configure<TokenOptions>(options =>
			{
                options.Issuer = _options.Issuer;
				options.Audience = _options.Audience;
				options.SigningCredentials = new SigningCredentials(_options.SigningKey, SecurityAlgorithms.HmacSha256);
			});
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

			var tokenValidationParameters = new TokenValidationParameters
			{
				ValidateIssuer = true,
				ValidIssuer = _options.Issuer,

				ValidateAudience = true,
				ValidAudience = _options.Audience,

				ValidateIssuerSigningKey = true,
				IssuerSigningKey = _options.SigningKey,

				RequireExpirationTime = true,
				ValidateLifetime = true,

				ClockSkew = TimeSpan.Zero
			};

			app.UseJwtBearerAuthentication(new JwtBearerOptions
			{
				AutomaticAuthenticate = true,
				AutomaticChallenge = true,
				TokenValidationParameters = tokenValidationParameters
			});

			app.UseCors(x =>
			{
				x.AllowAnyHeader();
				x.AllowAnyMethod();
				x.AllowAnyOrigin();
			});

            app.UseMvc();

            //Runtime.ConnectionString = Configuration.GetConnectionString("CnnStr");
        }
    }
}
