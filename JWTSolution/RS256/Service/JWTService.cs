using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using RS256.Model;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;

namespace RS256.Service
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
            string keyDir = Directory.GetCurrentDirectory();
            if (RSAHelper.TryGetKeyParameters(keyDir, true, out RSAParameters parameters) == false)
            {
                parameters = RSAHelper.GenerateAndSaveKey(keyDir);
            }
            var creds = new SigningCredentials(new RsaSecurityKey(parameters), SecurityAlgorithms.RsaSha256Signature);

            var token = new JwtSecurityToken
                (
                    issuer: tokenOptions.Issuer,
                    audience: tokenOptions.Audience,
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(30),
                    notBefore: DateTime.Now.AddSeconds(1),
                    signingCredentials: creds
                );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
