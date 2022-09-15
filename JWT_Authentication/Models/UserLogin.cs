using System.ComponentModel.DataAnnotations;

namespace JWT_Authentication.Models
{
    public class UserLogin
    {
        [Required(ErrorMessage ="User Name is Required")]
        public string? UserName { get; set; }
        [Required(ErrorMessage ="Password is Required")]
        public string? Password { get; set; }
    }
}
