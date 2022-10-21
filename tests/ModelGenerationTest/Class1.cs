using EAVFramework;
using EAVFW.Extensions.OIDCIdentity;
using MC.Models;
using Microsoft.Extensions.DependencyInjection;
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
    }
}

