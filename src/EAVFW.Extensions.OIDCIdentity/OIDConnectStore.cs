using EAVFramework;
using EAVFramework.Endpoints;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System;

#nullable enable

namespace EAVFW.Extensions.OIDCIdentity
{
    public class OIDConnectStore<TContext, TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType, TOpenIdConnectToken,
        TOpenIdConnectTokenType, TOpenIdConnectTokenStatus, TAllowedGrantType, TOpenIdConnectAuthorizationScope, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes,
        TAllowedGrantTypeValue, TOpenIdConnectScope, TOpenIdConnectScopeResource, TOpenIdConnectResource, TOpenIdConnectIdentityResource>
        where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
        where TOpenIdConnectAuthorization : DynamicEntity, IOpenIdConnectAuthorization<TOpenIdConnectClient, TOpenIdConnectToken, TOpenIdConnectAuthorizationScope, TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType>
        where TOpenIdConnectAuthorizationStatus : struct, IConvertible
        where TOpenIdConnectToken : DynamicEntity, IOpenIdConnectToken<TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectTokenStatus, TOpenIdConnectTokenType>
        where TOpenIdConnectTokenStatus : struct, IConvertible
        where TOpenIdConnectTokenType : struct, IConvertible
        where TAllowedGrantType : DynamicEntity, IAllowedGrantType<TAllowedGrantTypeValue>
        where TOpenIdConnectAuthorizationScope : DynamicEntity, IOpenIdConnectAuthorizationScope<TOpenIdConnectIdentityResource>, new()
         where TOpenIdConnectClientTypes : struct, IConvertible
         where TOpenIdConnectClientConsentTypes : struct, IConvertible
        where TAllowedGrantTypeValue : struct, IConvertible
            where TOpenIdConnectScopeResource : DynamicEntity, IOpenIdConnectScopeResource<TOpenIdConnectResource, TOpenIdConnectIdentityResource>
            where TOpenIdConnectResource : DynamicEntity, IOpenIdConnectResource<TOpenIdConnectScopeResource>
          where TOpenIdConnectScope : DynamicEntity, IOpenIdConnectScope<TOpenIdConnectScopeResource>
        where TOpenIdConnectIdentityResource : DynamicEntity, IOpenIdConnectIdentityResource
          where TOpenIdConnectAuthorizationType : struct, IConvertible
        where TContext : DynamicContext
    {
        /// <summary>
        /// Gets the memory cache associated with the current store.
        /// </summary>
        protected IMemoryCache Cache { get; }
        protected IPrincipalService<
            TOpenIdConnectAuthorization,
            TOpenIdConnectClient,
            TAllowedGrantType,
            TAllowedGrantTypeValue,
            TOpenIdConnectClientTypes,
            TOpenIdConnectClientConsentTypes,
            TOpenIdConnectAuthorizationStatus,
            TOpenIdConnectAuthorizationType,
            TOpenIdConnectAuthorizationScope,
            TOpenIdConnectIdentityResource,
            TOpenIdConnectToken,
            TOpenIdConnectTokenStatus,
            TOpenIdConnectTokenType,
            TOpenIdConnectScopeResource,
            TOpenIdConnectResource,
            TOpenIdConnectScope
            > PrincipalService
        { get; }

        /// <summary>
        /// Gets the database context associated with the current store.
        /// </summary>
        protected EAVDBContext<TContext> Context { get; }

        /// <summary>
        /// Gets the options associated with the current store.
        /// </summary>
        protected IOptionsMonitor<OpenIddictEAVFrameworkOptions> Options { get; }

        public OIDConnectStore(
           IMemoryCache cache,
           IPrincipalService<
            TOpenIdConnectAuthorization,
            TOpenIdConnectClient,
            TAllowedGrantType,
            TAllowedGrantTypeValue,
            TOpenIdConnectClientTypes,
            TOpenIdConnectClientConsentTypes,
            TOpenIdConnectAuthorizationStatus,
            TOpenIdConnectAuthorizationType,
            TOpenIdConnectAuthorizationScope,
            TOpenIdConnectIdentityResource,
            TOpenIdConnectToken,
            TOpenIdConnectTokenStatus,
            TOpenIdConnectTokenType,
            TOpenIdConnectScopeResource,
            TOpenIdConnectResource,
            TOpenIdConnectScope
            > principalService,
           EAVDBContext<TContext> context,
           IOptionsMonitor<OpenIddictEAVFrameworkOptions> options)
        {
            Cache = cache;
            PrincipalService = principalService;
            Context = context;
            Options = options;
        }


        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TApplication"/> entity.
        /// </summary>
        protected DbSet<TOpenIdConnectClient> Applications => Context.Set<TOpenIdConnectClient>();

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TAuthorization"/> entity.
        /// </summary>
        protected DbSet<TOpenIdConnectAuthorization> Authorizations => Context.Set<TOpenIdConnectAuthorization>();

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TToken"/> entity.
        /// </summary>
        protected DbSet<TOpenIdConnectToken> Tokens => Context.Set<TOpenIdConnectToken>();

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="OpenIdConnectScope"/> entity.
        /// </summary>
        protected DbSet<TOpenIdConnectScope> Scopes => Context.Set<TOpenIdConnectScope>();
    }


}