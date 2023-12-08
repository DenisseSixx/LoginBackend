using System.ComponentModel.DataAnnotations;

namespace LoginBackend.Models;

public class CredencialesUsuario
{
    [EmailAddress]
    public required string email { get; set; }
    [Required]
    public string password { get; set; }
}
