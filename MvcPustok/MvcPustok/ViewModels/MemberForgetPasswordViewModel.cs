using System.ComponentModel.DataAnnotations;

namespace MvcPustok.ViewModels {
	public class MemberForgetPasswordViewModel {
		[Required]
		[EmailAddress]
		[MaxLength(50)]
		[MinLength(5)]
		public string Email { get; set; }
	}
}
