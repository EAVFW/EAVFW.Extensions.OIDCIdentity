using Microsoft.Extensions.DependencyInjection;

#nullable enable

namespace EAVFW.Extensions.OIDCIdentity
{
    public class OpenIddictEAVFrameworkBuilder
    {
        private IServiceCollection _services;

        public OpenIddictEAVFrameworkBuilder(IServiceCollection services)
        {
            _services = services;
        }
    }

     
}