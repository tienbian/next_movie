using System.ComponentModel.DataAnnotations;

namespace nextMovie.Authentication
{
    public class RegisterValidate
    {
        [Required(ErrorMessage = "User Name is required")]
        public string Username { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Full Name is required")]
        public string FullName { get; set; }
    }
}