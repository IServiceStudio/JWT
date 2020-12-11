using HS256.Model;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace HS256.Service
{
    public class JWTService : IJWTService
    {
        private readonly JWTTokenOptions tokenOptions;

        public JWTService(IOptionsMonitor<JWTTokenOptions> optionsMonitor)
        {
            this.tokenOptions = optionsMonitor.CurrentValue;
        }

        public string GetToken(User user)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name,user.Name),
                new Claim(ClaimTypes.Email,user.Email),
                new Claim("Account",user.Account),
                new Claim(ClaimTypes.Role,user.Role)
            };
            //对称加密
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenOptions.SecurityKey));
            var creds = new SigningCredentials(key,SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken
                (
                    issuer: tokenOptions.Issuer,
                    audience: tokenOptions.Audience,
                    claims:claims,
                    expires:DateTime.Now.AddMinutes(30),
                    notBefore:DateTime.Now.AddSeconds(1),
                    signingCredentials: creds
                );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
