using System.ComponentModel.DataAnnotations;

namespace JWT_Authentication.Models
{
    public class UserRegistration
    {
        [Required(ErrorMessage ="User Name is Required")]
        public string? UserName { get; set; }
        [Required(ErrorMessage ="Email is Required")]
        [EmailAddress]
        public string? Email { get; set; }
        [Required(ErrorMessage ="Password is Required")]
        public string? Password { get; set; }
    }
}
