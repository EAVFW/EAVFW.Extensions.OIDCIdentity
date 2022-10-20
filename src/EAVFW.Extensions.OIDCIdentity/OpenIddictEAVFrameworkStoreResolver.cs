using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using System;

#nullable enable

namespace EAVFW.Extensions.OIDCIdentity
{
    public class OpenIddictEAVFrameworkStoreResolver :
        IOpenIddictApplicationStoreResolver,
        IOpenIddictAuthorizationStoreResolver,
        IOpenIddictScopeStoreResolver,
        IOpenIddictTokenStoreResolver
    {
        private readonly IServiceProvider _serviceProvider;

        public OpenIddictEAVFrameworkStoreResolver(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        }
        public IOpenIddictApplicationStore<TApplication> Get<TApplication>() where TApplication : class
        {
            return _serviceProvider.GetRequiredService<IOpenIddictApplicationStore<TApplication>>();
        }

        IOpenIddictAuthorizationStore<IOpenIdConnectAuthorization> IOpenIddictAuthorizationStoreResolver.Get<IOpenIdConnectAuthorization>()
        {
            return _serviceProvider.GetRequiredService<IOpenIddictAuthorizationStore<IOpenIdConnectAuthorization>>();
        }

        IOpenIddictTokenStore<OpenIdConnectToken> IOpenIddictTokenStoreResolver.Get<OpenIdConnectToken>()
        {
            return _serviceProvider.GetRequiredService<IOpenIddictTokenStore<OpenIdConnectToken>>();
        }

        IOpenIddictScopeStore<TScope> IOpenIddictScopeStoreResolver.Get<TScope>()
        {
            return _serviceProvider.GetRequiredService<IOpenIddictScopeStore<TScope>>();
        }
    }

     
}