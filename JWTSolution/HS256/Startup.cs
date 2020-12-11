using HS256.Model;
using HS256.Service;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Threading.Tasks;

namespace HS256
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.Configure<JWTTokenOptions>(Configuration.GetSection("JWTTokenOptions"));
            services.AddTransient<IJWTService, JWTService>();

            #region Jwt校验
            var tokenOptions = new JWTTokenOptions();
            Configuration.Bind("JWTTokenOptions", tokenOptions);

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = tokenOptions.Issuer,
                        ValidAudience = tokenOptions.Audience,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenOptions.SecurityKey))
                    };
                });

            //授权方式 Scheme、Role、Policy
            services.AddAuthorization(options =>
            {
                //内置策略
                options.AddPolicy("AdminPolicy", policy => policy
                    .RequireRole("Admin")
                    .RequireUserName("Admin")
                    .RequireClaim("Email"));

                //自定义策略 
                options.AddPolicy("EmailRequirement", policy => policy.Requirements.Add(new EmailRequirement()));
            });

            //入驻自定义策略服务
            services.AddSingleton<IAuthorizationHandler, EmailHandler>();
            #endregion
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            //启用鉴权
            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public class EmailRequirement : IAuthorizationRequirement
    {
    }
    public class EmailHandler : AuthorizationHandler<EmailRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, EmailRequirement requirement)
        {
            if (context.User != null && context.User.HasClaim(c => c.Type == "Email"))
            {
                var email = context.User.FindFirst(c => c.Type == "Email").Value;
                if (email.EndsWith("@outlook.com", System.StringComparison.OrdinalIgnoreCase))
                {
                    context.Succeed(requirement);
                }
            }
            return Task.CompletedTask;
        }
    }
}
