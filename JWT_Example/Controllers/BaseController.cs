using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace JWT_Example.Controllers
{
    public class BaseController : Controller
    {
        public BaseController()
        {
        }

        public async Task<IActionResult> Response(object result, string errormessage)
        {
            if (string.IsNullOrEmpty(errormessage))
            {
                return Ok(new
                {
                    success = true,
                    data = result
                });
            }
            else
            {
                return BadRequest(new
                {
                    success = false,
                    errors = errormessage
                });
            }
        }
    }
}
