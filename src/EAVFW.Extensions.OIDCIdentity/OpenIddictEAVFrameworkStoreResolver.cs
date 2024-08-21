using EAVFramework;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using System;



namespace EAVFW.Extensions.OIDCIdentity
{
    public interface IStoreResolver : IOpenIddictApplicationStoreResolver,
        IOpenIddictAuthorizationStoreResolver,
        IOpenIddictScopeStoreResolver,
        IOpenIddictTokenStoreResolver
    {

    }

    public class DynamicOpenIddictEAVFrameworkStoreResolver<TContext> : IStoreResolver
        where TContext:DynamicContext

    {
        private readonly IServiceProvider _serviceProvider;

        public DynamicOpenIddictEAVFrameworkStoreResolver(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        }
        public IOpenIddictApplicationStore<TApplication> Get<TApplication>() where TApplication : class
        {

            return _serviceProvider.GetDynamicService<TContext>(typeof(OpenIddictEAVFrameowrkApplicationStore<,,,,,,,,,,,,,,,,>)) as IOpenIddictApplicationStore<TApplication>; //.GetRequiredService<IOpenIddictApplicationStore<TApplication>>();
        }

        IOpenIddictAuthorizationStore<IOpenIdConnectAuthorization> IOpenIddictAuthorizationStoreResolver.Get<IOpenIdConnectAuthorization>()
        {
            return _serviceProvider.GetDynamicService<TContext>(typeof(OpenIddictEAVFrameworkAuthorizationStore<,,,,,,,,,,,,,,,,>)) as IOpenIddictAuthorizationStore<IOpenIdConnectAuthorization>; //.GetRequiredService<IOpenIddictApplicationStore<TApplication>>();
        }

        IOpenIddictTokenStore<OpenIdConnectToken> IOpenIddictTokenStoreResolver.Get<OpenIdConnectToken>()
        {
            return _serviceProvider.GetDynamicService<TContext>(typeof(OpenIddictEAVFrameworkTokenStore<,,,,,,,,,,,,,,,,>)) as IOpenIddictTokenStore<OpenIdConnectToken>; //.GetRequiredService<IOpenIddictApplicationStore<TApplication>>();

        }

        IOpenIddictScopeStore<TScope> IOpenIddictScopeStoreResolver.Get<TScope>()
        {
            return _serviceProvider.GetDynamicService<TContext>(typeof(OpenIddictEAVFrameowrkScopeStore<,,,,,,,,,,,,,,,,>)) as IOpenIddictScopeStore<TScope>; //.GetRequiredService<IOpenIddictApplicationStore<TApplication>>();

        }
    }

    public class OpenIddictEAVFrameworkStoreResolver : IStoreResolver
       
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