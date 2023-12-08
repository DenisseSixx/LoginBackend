using LoginBackend.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LoginBackend.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CuentasController : Controller
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IConfiguration _config;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly ApplicationDbContext _context;

    public CuentasController(
        UserManager<IdentityUser> userManager,
        IConfiguration config,
        SignInManager<IdentityUser> signInManager, 
        ApplicationDbContext context
        )
    {
        _userManager = userManager;
        _config = config;
        _signInManager = signInManager;
        _context = context;
    }

    [HttpPost("registrar")]
    public async Task<ActionResult<RespuestaAutenticacion>> Registrar(CredencialesUsuario credencialesUsuario)
    {
        var usuario = new IdentityUser
        {
            UserName = credencialesUsuario.email,
            Email = credencialesUsuario.email
        };
        var resultado = await _userManager.CreateAsync(usuario, credencialesUsuario.password);
        if (resultado.Succeeded)
        {
            return await ConstruirToken(credencialesUsuario);
        }
        return BadRequest(resultado.Errors);
    }

    private async Task<ActionResult<RespuestaAutenticacion>> ConstruirToken(CredencialesUsuario credencialesUsuario)
    {
        var claims = new List<Claim>()
        {
            new Claim("email",credencialesUsuario.email)
        };
        var usuario = await _userManager.FindByEmailAsync(credencialesUsuario.email);
        var claimsRoles = await _userManager.GetClaimsAsync(usuario);

        claims.AddRange(claims);

        var llave = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["LlaveJWT"]));
        var creds = new SigningCredentials(llave, SecurityAlgorithms.HmacSha256);

        var expiracion = DateTime.UtcNow.AddDays(1);

        var securityToken = new JwtSecurityToken(issuer: null, audience: null, claims: claims, expires: expiracion, signingCredentials: creds);

        return new RespuestaAutenticacion
        {
            token = new JwtSecurityTokenHandler().WriteToken(securityToken),
            expiracion = expiracion,
        };
    }


    [HttpGet("RenovarToken")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]

    public async Task<ActionResult<RespuestaAutenticacion>> Renovar()
    {

        var emailClaims = HttpContext.User.Claims.Where(x => x.Type == ClaimTypes.Email).Select(x => x.Value).FirstOrDefault();
        var credencialesUsuario = new CredencialesUsuario() { email = emailClaims };

        return await ConstruirToken(credencialesUsuario);
    }

    [HttpPost("Login")]
    public async Task<ActionResult<RespuestaAutenticacion>> Login(CredencialesUsuario credencialesUsuario)
    {
        var resultado = await _signInManager.PasswordSignInAsync(
            credencialesUsuario.email,
            credencialesUsuario.password,
            isPersistent: false,
            lockoutOnFailure: false);
        if (resultado.Succeeded)
        {
            return await ConstruirToken(credencialesUsuario);
        }
        else
        {
            return BadRequest("Login Incorrecto");
        }
    }



    [HttpPost("Favorito")]
    public ActionResult AgregarPersonajeFavorito([FromBody] Favoritos favorito)
    {
        if (favorito == null)
        {
            return BadRequest("Datos inválidos");
        }

        // Puedes realizar validaciones adicionales aquí
        var personajeExistente = _context.Favoritos
            .FirstOrDefault(p => p.UserId == favorito.UserId && p.CharacterId == favorito.CharacterId);

        if (personajeExistente != null)
        {
            return BadRequest("El personaje ya está en la lista de favoritos");
        }

        _context.Favoritos.Add(favorito);
        _context.SaveChangesAsync();

        return Ok();
    }

    [HttpDelete("EliminarPersonajeFavorito")]
    public ActionResult EliminarPersonajeFavorito([FromBody] Favoritos favorito)
    {
        if (favorito == null)
        {
            return BadRequest("Datos inválidos");
        }

        // Puedes realizar validaciones adicionales aquí
        var personajeExistente = _context.Favoritos
            .FirstOrDefault(p => p.UserId == favorito.UserId && p.CharacterId == favorito.CharacterId);

        if (personajeExistente == null)
        {
            return NotFound("El personaje no se encuentra en la lista de favoritos");
        }

        _context.Favoritos.Remove(personajeExistente);
        _context.SaveChangesAsync();

        return Ok();
    }

    [HttpGet("ObtenerPersonajesFavoritos/{userId}")]
    public IActionResult ObtenerPersonajesFavoritos(string userId)
    {
        var personajesFavoritos = _context.Favoritos
            .Where(p => p.UserId == userId)
            .ToList();

        return Ok(personajesFavoritos);
    }
}
