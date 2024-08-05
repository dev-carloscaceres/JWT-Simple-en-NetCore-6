using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ExampleJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        // Lista simple de usuarios para la autenticación
        private static readonly List<User> Users = new List<User>
        {
            new User { Username = "user0", Password = "ExampleP@ssw0rd" },
            new User { Username = "user1", Password = "Password1" },
            new User { Username = "user2", Password = "Password2" }
        };
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] User login)
        {
            // Aquí validarías al usuario con tus propias reglas (e.g., base de datos)
            var user = Users.FirstOrDefault(u => u.Username == login.Username && u.Password == login.Password);
            if (user == null)
                return Unauthorized();

            var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim(ClaimTypes.Name, login.Username)
                    }),
                    Expires = DateTime.UtcNow.AddDays(1), // Tiempo de sesión
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                return Ok(new { Token = tokenString });

        }
    }

    public class User
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
