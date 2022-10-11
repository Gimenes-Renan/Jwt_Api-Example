using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Jwt_Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class JwtController : ControllerBase
    {
        [HttpPost]
        public IActionResult Login([FromBody] Usuario loginDetalhes)
        {
            var tokenString = GerarTokenJWT(loginDetalhes);
            return Ok(new { token = tokenString });
        }

        private string GerarTokenJWT(Usuario loginDetalhes)
        {
            var issuer = "AlgumIssuer";
            var audience = "AlgumAudience";
            var expiry = DateTime.Now.AddMinutes(120);
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("f52485b529de9ae51e0521dfa2806a8f"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            IEnumerable<Claim> claims = new List<Claim>()
            {
                new Claim("nome", loginDetalhes.Nome)
            };
            var token = new JwtSecurityToken(issuer: issuer, audience: audience,
                expires: expiry, signingCredentials: credentials, claims: claims);
            var tokenHandler = new JwtSecurityTokenHandler();
            var stringToken = tokenHandler.WriteToken(token);
            return stringToken;
        }

        [HttpGet]
        [Authorize]
        public IActionResult Get()
        {
            var handler = new JwtSecurityTokenHandler();
            string authHeader = Request.Headers["Authorization"];
            authHeader = authHeader.Replace("Bearer ", "");
            var tokenS = handler.ReadToken(authHeader) as JwtSecurityToken;
            var validade = tokenS.ValidTo.ToString();
            return Ok("OK! Validade: " + validade + " - Claims: " + tokenS.Claims.ElementAtOrDefault(0));
        }
    }
}
