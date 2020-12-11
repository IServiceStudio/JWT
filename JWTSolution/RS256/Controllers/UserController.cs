using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RS256.Service;

namespace RS256.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IJWTService jwtService;

        public UserController(IJWTService jwtService)
        {
            this.jwtService = jwtService;
        }
        [HttpGet("login")]
        public IActionResult Login(string loginName, string loginPwd)
        {
            if (loginName == "admin" && loginPwd == "password")
            {
                return Ok(jwtService.GetToken(new Model.User
                {
                    Account = loginName,
                    Age = 20,
                    Email = "IService@outlook.com",
                    Name = "IService",
                    Phone = "156****4523",
                    Role = "admin",
                    Sex = "男"
                }));
            }
            return NotFound("用户名或密码错误");
        }

        [HttpGet]
        [Authorize]
        public IActionResult Get()
        {
            return Ok("ok");
        }
    }
}
