using System.ComponentModel.DataAnnotations;

namespace nextMovie.Authentication
{
    public class Login
    {
        [Required(ErrorMessage = "User Name is required")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

        public string? Email { get; set; }

    }
}