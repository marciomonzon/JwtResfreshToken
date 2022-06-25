using JwtRefreshToken.Models;
using JwtRefreshToken.Repository;
using JwtRefreshToken.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtRefreshToken.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        [HttpPost("login")]
        public async Task<ActionResult<dynamic>> AuthenticateAsync([FromBody] User model)
        {
            var user = UserRepository.Get(model.UserName, model.Password);

            if (user == null)
                return NotFound(new { message = "Incorrect user or password. Please try again." });

            var token = TokenService.GenerateToken(user);
            var resfreshToken = TokenService.GenerateRefreshToken();
            TokenService.SaveResfreshToken(user.UserName, resfreshToken);

            // hide password
            user.Password = "";

            // retorna dados
            return new
            {
                user = user,
                token = token,
                refreshToken = resfreshToken
            };
        }

        [HttpPost("refresh")]
        public IActionResult Refresh([FromBody] RefreshTokenModel model)
        {
            var principal = TokenService.GetPrincipalFromExpiredToken(model.Token);
            var username = principal.Identity.Name;
            var savedRefreshToken = TokenService.GetRefreshToken(username);
            if (savedRefreshToken != model.RefreshToken)
                throw new SecurityTokenException("Invalid refresh");

            var newJwtToken = TokenService.GenerateToken(principal.Claims);
            var newRefreshToken = TokenService.GenerateRefreshToken();

            TokenService.DeleteRefreshToken(username, model.RefreshToken);
            TokenService.SaveResfreshToken(username, newRefreshToken);

            return new ObjectResult(new
            {
                token = newJwtToken,
                refreshToken = newRefreshToken
            });
        }
    }
}
