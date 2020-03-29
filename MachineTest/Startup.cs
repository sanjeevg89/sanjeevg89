using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(MachineTest.Startup))]
namespace MachineTest
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
