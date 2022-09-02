using System.ComponentModel.DataAnnotations;

namespace IdentitySocialAuth.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
