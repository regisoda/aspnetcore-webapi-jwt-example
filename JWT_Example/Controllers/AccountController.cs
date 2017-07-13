using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using JWT_Example.Models;
using JWT_Example.Security;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace JWT_Example.Controllers
{
    public class AccountController: BaseController
    {
        private readonly TokenOptions _tokenOptions;
        private readonly JsonSerializerSettings _serializerSettings;

        public AccountController(IOptions<TokenOptions> jwtOptions)
        {
            _tokenOptions = jwtOptions.Value;
            ThrowIfInvalidOptions(_tokenOptions);

            _serializerSettings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented,
                ContractResolver = new CamelCasePropertyNamesContractResolver()
            };
        }

		[HttpPost]
		[AllowAnonymous]
		[Route("v1/authenticate")]
        public async Task<IActionResult> Post([FromForm] AuthenticateUser form)
		{
			if (form == null)
				return await Response(null, "Usuário ou senha inválidos");

            var identity = await GetClaims(form.Username, form.Password);
			if (identity == null)
				return await Response(null, "Usuário ou senha nao conferem");

			var claims = new[]
			{
				new Claim(JwtRegisteredClaimNames.UniqueName, identity.Name),
				new Claim(JwtRegisteredClaimNames.NameId, identity.Name),
				new Claim(JwtRegisteredClaimNames.Email, string.Empty),
				new Claim(JwtRegisteredClaimNames.Sub, form.Username),
				new Claim(JwtRegisteredClaimNames.Jti, await _tokenOptions.JtiGenerator()),
				new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(_tokenOptions.IssuedAt).ToString(), ClaimValueTypes.Integer64),
				identity.FindFirst("JWT_Example")
			};

			var jwt = new JwtSecurityToken(
				issuer: _tokenOptions.Issuer,
				audience: _tokenOptions.Audience,
				claims: claims.AsEnumerable(),
				notBefore: _tokenOptions.NotBefore,
				expires: _tokenOptions.Expiration,
				signingCredentials: _tokenOptions.SigningCredentials);

			var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

			var response = new
			{
				token = encodedJwt,
				expires = (int)_tokenOptions.ValidFor.TotalSeconds,
                //expires = _tokenOptions.Expiration,
				user = new
				{
                    authenticated = identity.IsAuthenticated,
					username = identity.Name
				}
			};

			var json = JsonConvert.SerializeObject(response, _serializerSettings);
			return new OkObjectResult(json);
		}

		[HttpPost]
		[AllowAnonymous]
		[Route("v1/token/validate")]
		public async Task<IActionResult> ValidarToken([FromBody]string token)
		{
			var validationParameters = new TokenValidationParameters()
			{
				ValidIssuer = _tokenOptions.Issuer,
				ValidAudience = _tokenOptions.Audience,
				IssuerSigningKey = _tokenOptions.SigningKey,
				RequireExpirationTime = true
			};

			var tokenHandler = new JwtSecurityTokenHandler();
			SecurityToken securityToken = null;

			try
			{
				tokenHandler.ValidateToken(token, validationParameters, out securityToken);
			}
			catch (Exception ex)
			{
                return await Response(null, $"Erro validando token: {ex.Message}");
			}

            if (securityToken != null)
            {
                return await Response(securityToken, null);
            }

            return await Response(null, "Nao foi possivel validar o token");
		}

        private static void ThrowIfInvalidOptions(TokenOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (options.ValidFor <= TimeSpan.Zero)
                throw new ArgumentException("O período deve ser maior que zero", nameof(TokenOptions.ValidFor));

            if (options.SigningCredentials == null)
                throw new ArgumentNullException(nameof(TokenOptions.SigningCredentials));

            if (options.JtiGenerator == null)
                throw new ArgumentNullException(nameof(TokenOptions.JtiGenerator));
        }

        private static long ToUnixEpochDate(DateTime date)
          => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);

        private Task<ClaimsIdentity> GetClaims(string username, string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                return Task.FromResult<ClaimsIdentity>(null);

            if (username == "usr" && password == "123")
            {
                return Task.FromResult(new ClaimsIdentity(
                    new GenericIdentity(username, "Token"),
                    new[] {
                        new Claim("JWT_Example", "User")
                    }));
            }

			if (username == "adm" && password == "123")
			{
				return Task.FromResult(new ClaimsIdentity(
					new GenericIdentity(username, "Token"),
					new[] {
						new Claim("JWT_Example", "Admin")
					}));
			}

			return Task.FromResult<ClaimsIdentity>(null);
        }
    }
}
