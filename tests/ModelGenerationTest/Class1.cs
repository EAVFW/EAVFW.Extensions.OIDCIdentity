using EAVFramework;
using EAVFW.Extensions.OIDCIdentity;
using MC.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using System;

namespace ModelGenerationTest
{
    public class Class1 
    {
        public Type Test = typeof(OpenIddictEAVFrameworkeExtensions);
    }
   
    public static class Extensions
    {
        public static void Register<TContext>(this IServiceCollection services) where TContext: DynamicContext
        {
           services.AddOpenIdConnect<TContext, OpenIdConnectAuthorization, OpenIdConnectClient, AllowedGrantType, AllowedGrantTypeValue, OpenIdConnectClientTypes, OpenIdConnectClientConsentTypes, OpenIdConnectAuthorizationStatus, OpenIdConnectAuthorizationType, OpenIdConnectAuthorizationScope, OpenIdConnectIdentityResource, OpenIdConnectToken, OpenIdConnectTokenStatus, OpenIdConnectTokenType, OpenIdConnectScopeResource, OpenIdConnectResource, OpenIdConnectScope>();
        }

        public static void Register<TContext,TClientManager>(this IServiceCollection services) 
            where TContext : DynamicContext
            where TClientManager : ClientManager<OpenIdConnectClient, AllowedGrantType, OpenIdConnectClientTypes, OpenIdConnectClientConsentTypes, AllowedGrantTypeValue>
        {
            services.AddOpenIdConnect<TContext,TClientManager, OpenIdConnectAuthorization, OpenIdConnectClient, AllowedGrantType, AllowedGrantTypeValue, OpenIdConnectClientTypes, OpenIdConnectClientConsentTypes, OpenIdConnectAuthorizationStatus, OpenIdConnectAuthorizationType, OpenIdConnectAuthorizationScope, OpenIdConnectIdentityResource, OpenIdConnectToken, OpenIdConnectTokenStatus, OpenIdConnectTokenType, OpenIdConnectScopeResource, OpenIdConnectResource, OpenIdConnectScope>();
        }
    }
}

