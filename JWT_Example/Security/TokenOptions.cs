using System;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace JWT_Example.Security
{
    public class TokenOptions
    {
		private const string ISSUER = "c1f51f42";
		private const string AUDIENCE = "c6bbbb645024";
		private const string SECRET_KEY = "c1f51f42-5727-4d15-b787-c6bbbb645024";
        private readonly SymmetricSecurityKey _signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(SECRET_KEY));

        public TokenOptions()
        {
            //Issuer = ISSUER;
            //Audience = AUDIENCE;
            SigningKey = _signingKey;
        }

        public string Issuer { get; set; } = ISSUER;

        public string Subject { get; set; } = AUDIENCE;

        public string Audience { get; set; } 

        public DateTime NotBefore { get; set; } = DateTime.UtcNow;

        public DateTime IssuedAt { get; set; } = DateTime.UtcNow;

        public TimeSpan ValidFor { get; set; } = TimeSpan.FromDays(2);

        public DateTime Expiration => IssuedAt.Add(ValidFor);

        public Func<Task<string>> JtiGenerator => () => Task.FromResult(Guid.NewGuid().ToString());

        public SigningCredentials SigningCredentials { get; set; }

        public SymmetricSecurityKey SigningKey { get; set; }
    }

}
