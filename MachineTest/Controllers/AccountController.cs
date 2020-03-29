using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using MachineTest.Models;
using System.Collections.Generic;
using System.IO;
//using iTextSharp.text;
//using iTextSharp.text.pdf;
using iTextSharp;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.tool.xml;
using iTextSharp.text.html.simpleparser;
using System.Web.Helpers;

namespace MachineTest.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager )
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set 
            { 
                _signInManager = value; 
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl, string option)
        {
            ViewBag.ReturnUrl = returnUrl;
            using (var databaseContext = new MachineTest.EmployeeEntities1())
            {
                var user = (databaseContext.Employees.FirstOrDefault());
                return View("UserLandingView1", databaseContext.Employees.ToList());
            }
                return View("Login");
        }
        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);

            }

            using (var databaseContext = new MachineTest.EmployeeEntities1())
            {
                var user = (databaseContext.Employees.Where(a => a.Name.Equals(model.UserName)).FirstOrDefault());
                var password = (databaseContext.Employees.Where(a => a.Password.Equals(model.Password)).FirstOrDefault());
                if (user != null && password != null)
                {
                    Session["UserID"] = user.Name;
                    Session["Password"] = user.Password;

                }
                var result = await SignInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe, shouldLockout: false);
                switch (result)
                {
                    case SignInStatus.Success:
                        //    return RedirectToLocal(returnUrl);
                        return View("UserLandingView1", databaseContext.Employees.ToList());
                    case SignInStatus.LockedOut:
                        return View("Lockout");
                    case SignInStatus.RequiresVerification:
                        return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                    case SignInStatus.Failure:
                    default:
                        ModelState.AddModelError("", "Invalid login attempt.");
                        return View(model);
                }
            }
        }
        //
        // GET: /Account/VerifyCode
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in IdentityConfig
            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent:  model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            var list = new List<CheckModel>
            {
                new CheckModel {Id=1,Hobbies="Reading",Checked=false },
                new CheckModel {Id=2,Hobbies="Swimming",Checked=false },
                new CheckModel {Id=3,Hobbies="Watching Movies",Checked=false },
                new CheckModel {Id=4,Hobbies="Playing",Checked=false },
            };
            ViewBag.hobbies = list;
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(Employee employee,FormCollection check)
        {
            try
            {
                if (ModelState.IsValid)
                {

                    ViewBag.QualificationList= new List<SelectListItem>()
                {

                new SelectListItem
                {
                    Text = "BE",
                    Value = "1"
                },
                new SelectListItem
                {
                    Text = "BSc",
                    Value = "1"
                },
                new SelectListItem
                {
                    Text = "MSc",
                    Value = "1"
                },
                new SelectListItem
                {
                    Text = "MCA",
                    Value = "1"
                }
                };

                    using (var databaseContext = new MachineTest.EmployeeEntities1())
                    {
                        var newUser = databaseContext.Employees.Create();
                        newUser.Name = employee.Name;
                        newUser.Password = employee.Password;
                        newUser.BirthDate = employee.BirthDate;
                        newUser.Qualification =Convert.ToString(employee.QualificationList);
                        newUser.Experience = employee.Experience;
                        newUser.JoinningDate = employee.JoinningDate;
                        newUser.Salary = employee.Salary;
                        newUser.Designation = employee.Designation;
                        if (!String.IsNullOrEmpty(check["Hobbies"]))
                        newUser.Hobbies = check["Hobbies"];
                        databaseContext.Employees.Add(newUser);
                        databaseContext.SaveChanges();
                        return RedirectToAction("Index", "Home");
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Invalid Input");
                }

            }
            catch(System.Data.Entity.Validation.DbEntityValidationException ex)
            {
                Exception raise = ex;
                foreach (var validationError in ex.EntityValidationErrors)
                {
                    foreach (var item in validationError.ValidationErrors)
                    {
                        string message = string.Format("{0}:{1}", validationError.Entry.Entity.ToString(), item.ErrorMessage);
                        raise = new InvalidOperationException(message, raise);

                    }
                }
                throw raise;


            }
          
            // If we got this far, something failed, redisplay form
            return View(employee);
        }
        [HttpPost]
        [AllowAnonymous]
        public ActionResult Index(string option,string search)
        {
            using (var databaseContext = new MachineTest.EmployeeEntities1())
            {
                var user = (databaseContext.Employees.FirstOrDefault());
                
                    if (option=="Name" && !string.IsNullOrEmpty(search))
                    {
                        return View("UserLandingView1", databaseContext.Employees.Where(x=>x.Name==search).ToList());
                    }
                return View("UserLandingView1", databaseContext.Employees.ToList());
            }

           return View("");
        }

        [HttpPost]
        [AllowAnonymous]
        public FileResult Export(string GridHtml)
        {
            try {
                List<Employee> all = new List<Employee>();
                using (var databaseContext = new MachineTest.EmployeeEntities1())
                {
                    var user = (databaseContext.Employees.FirstOrDefault());
                   // if (!string.IsNullOrEmpty(Convert.ToString(Session["UserID"])) && !string.IsNullOrEmpty(Convert.ToString(Session["Password"])))
                    //{
                        all=databaseContext.Employees.ToList();
                    //}
                }
                WebGrid webGrid1 = new WebGrid(source: all, canPage: false,canSort:false);

                string gridHtml = webGrid1.GetHtml(
        columns:webGrid1.Columns(
        webGrid1.Column("Name", "Name"),
           webGrid1.Column("BirthDate", "BirthDate"),
           webGrid1.Column("Qualification", "Qualification"),
           webGrid1.Column("Experience", "Experience"),
           webGrid1.Column("JoinningDate", "JoinningDate"),
           webGrid1.Column("Salary", "Salary"),
           webGrid1.Column("Designation", "Designation"),
           webGrid1.Column("Hobbies", "Hobbies")
           )
           ).ToString();
                string exportData = String.Format("<html><head>{0}</head><body>{1}</body></html>", "<style>table{ border-spacing: 1px; border-collapse: separate;border - collapse: collapse, border: 1px solid #ccc; }"+
                    "th{backgroung-color:#BBDBFD;border:1px solid #ccc; border-width:1px}td{padding:8px;border-style:solid;border-color:#666666;background-color:#fffff;border:1px solid #ccc; border-width:1px}</style>", gridHtml);
                var bytes = System.Text.Encoding.UTF8.GetBytes(exportData);
                using (var input = new MemoryStream(bytes))
                {
                    var output = new MemoryStream();
                    var document = new iTextSharp.text.Document(PageSize.A4_LANDSCAPE, 10, 10, 100, 0);
                    var writer = PdfWriter.GetInstance(document, output);
                    writer.CloseStream = false;
                    document.Open();
                    var xmlWorker = iTextSharp.tool.xml.XMLWorkerHelper.GetInstance();
                    xmlWorker.ParseXHtml(writer, document, input, System.Text.Encoding.UTF8);
                    document.Close();
                    output.Position = 0;
                    return File(output, "application/pdf", "Grid.pdf");
                }
            }
            catch(Exception ex)
            {

            }
            return File("", "application/pdf", "Grid.pdf");
        }

        //
        // GET: /Account/ConfirmEmail
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var result = await UserManager.ConfirmEmailAsync(userId, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        //
        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.Email);
                if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                // string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                // var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);		
                // await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
                // return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/SendCode
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            var userId = await SignInManager.GetVerifiedUserIdAsync();
            if (userId == null)
            {
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/SendCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Generate the token and send it
            if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                return View("Error");
            }
            return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        //
        // GET: /Account/ExternalLoginCallback
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            // Sign in the user with this external login provider if the user already has a login
            var result = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
                case SignInStatus.Failure:
                default:
                    // If the user does not have an account, then prompt the user to create an account
                    ViewBag.ReturnUrl = returnUrl;
                    ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                    return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
            }
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }

            base.Dispose(disposing);
        }

        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion
    }
}