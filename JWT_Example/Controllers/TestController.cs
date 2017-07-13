using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace JWT_Example.Controllers
{
    public class TestController: BaseController
    {
		[HttpGet]
		[Route("v1/test")]
		[AllowAnonymous]
		public async Task<IActionResult> GetAnonymous()
		{
            return await Response("Running anonymous...", null);
		}

		[HttpGet]
		[Route("v2/test")]
		public async Task<IActionResult> GetAuthenticated()
		{
			return await Response("Running authenticated...", null);
		}
    }
}
