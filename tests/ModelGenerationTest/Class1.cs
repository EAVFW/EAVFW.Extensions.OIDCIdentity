﻿using EAVFramework;
using EAVFramework.Endpoints;
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
    public class EAVClientManager : EAVApplicationManager<DynamicContext, OpenIdConnectClient, OpenIdConnectSecret, AllowedGrantType, OpenIdConnectClientTypes, OpenIdConnectClientConsentTypes, AllowedGrantTypeValue>
    {
        public EAVClientManager(
            EAVDBContext<DynamicContext> context,
            IOpenIddictApplicationCache<OpenIdConnectClient> cache,
            ILogger<OpenIddictApplicationManager<OpenIdConnectClient>> logger,
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictApplicationStoreResolver resolver) : base(context, cache, logger, options, resolver)
        {
        }


    }

    public static class Extensions
    {
        public static void AddOpenIdConnect(this IServiceCollection services, EAVOpenIdConnectOptions options)
        {
            services.AddOpenIdConnect<DynamicContext, EAVClientManager>(options);
        }

        public static void AddOpenIdConnect<TContext>(this IServiceCollection services, EAVOpenIdConnectOptions options) where TContext : DynamicContext
        {
            services.AddOpenIdConnect<TContext, OpenIdConnectAuthorization, OpenIdConnectClient, OpenIdConnectSecret, AllowedGrantType, AllowedGrantTypeValue, OpenIdConnectClientTypes, OpenIdConnectClientConsentTypes, OpenIdConnectAuthorizationStatus, OpenIdConnectAuthorizationType, OpenIdConnectAuthorizationScope, OpenIdConnectIdentityResource, OpenIdConnectToken, OpenIdConnectTokenStatus, OpenIdConnectTokenType, OpenIdConnectScopeResource, OpenIdConnectResource, OpenIdConnectScope>(options);
        }

        public static void AddOpenIdConnect<TContext, TClientManager>(this IServiceCollection services, EAVOpenIdConnectOptions options)
            where TContext : DynamicContext
            where TClientManager : EAVApplicationManager<TContext, OpenIdConnectClient, OpenIdConnectSecret, AllowedGrantType, OpenIdConnectClientTypes, OpenIdConnectClientConsentTypes, AllowedGrantTypeValue>
        {
            services.AddOpenIdConnect<TContext, TClientManager, OpenIdConnectAuthorization, OpenIdConnectClient, OpenIdConnectSecret, AllowedGrantType, AllowedGrantTypeValue, OpenIdConnectClientTypes, OpenIdConnectClientConsentTypes, OpenIdConnectAuthorizationStatus, OpenIdConnectAuthorizationType, OpenIdConnectAuthorizationScope, OpenIdConnectIdentityResource, OpenIdConnectToken, OpenIdConnectTokenStatus, OpenIdConnectTokenType, OpenIdConnectScopeResource, OpenIdConnectResource, OpenIdConnectScope>(options);
        }
    }
}

