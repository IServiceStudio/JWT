using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace JWTSolution.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        [HttpGet("login")]
        public IActionResult Login(string loginName, string loginPwd)
        {
            if (loginName == "admin" && loginPwd == "password")
            {
                var claims = new Claim[]
                {
                    new Claim(ClaimTypes.Name,loginName),
                    new Claim(ClaimTypes.PrimarySid,Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Email,"iserviceStudio@outlook.com")
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("www.iservicestudio.com"));
                var signatrueKey = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var token = new JwtSecurityToken
                    (
                        issuer: "http://localhost:5000",
                        audience: "http://localhost:5000",
                        claims: claims,
                        expires: DateTime.Now.AddMinutes(5),
                        signingCredentials: signatrueKey
                    );

                return Ok(new JwtSecurityTokenHandler().WriteToken(token));
            }
            return NotFound("未找到此用户！");
        }

        [Authorize]
        public IActionResult Get(string jwt)
        {
            // 获取token内容的方法
            //1
            var jwtHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtToken = jwtHandler.ReadJwtToken(jwt);

            //2
            var sub = User.FindFirst(d => d.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")?.Value;

            //3
            var name = HttpContext.User.Identity.Name;
            var claims = HttpContext.User.Claims;
            var claimTypeVal = (from item in claims
                                where item.Type == ClaimTypes.Name
                                select item.Value).ToList();

            //4
            var claims4 = HttpContext.AuthenticateAsync().Result.Principal.Claims;

            return Ok(new { jwtToken, sub, claimTypeVal });
        }

        [HttpGet("userInfo")]
        public IActionResult UserInfo()
        {
            return Ok($"Service2:{DateTime.Now}");
        }
    }
}