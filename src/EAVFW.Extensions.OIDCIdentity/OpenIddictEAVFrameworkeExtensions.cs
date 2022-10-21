using EAVFramework;


using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Security.Claims;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;



namespace EAVFW.Extensions.OIDCIdentity
{



    public class TokenHandler<TOpenIdConnectClient, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue> : IOpenIddictServerHandler<HandleTokenRequestContext>
        where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
        where TOpenIdConnectClientTypes : struct, IConvertible
        where TOpenIdConnectClientConsentTypes : struct, IConvertible
        where TAllowedGrantTypeValue : struct, IConvertible
        where TAllowedGrantType : DynamicEntity, IAllowedGrantType<TAllowedGrantTypeValue>
    {
        private readonly ClientManager<TOpenIdConnectClient, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue> _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        public TokenHandler(ClientManager<TOpenIdConnectClient, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue> applicationManager, IOpenIddictScopeManager scopeManager)
        {
            _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));
            _scopeManager = scopeManager ?? throw new ArgumentNullException(nameof(scopeManager));
        }
        public async ValueTask HandleAsync(HandleTokenRequestContext context)
        {
            //var request = context.Request..GetOpenIddictServerRequest();
            var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
            if (application == null)
            {
                throw new InvalidOperationException("The application details cannot be found in the database.");
            }
            context.Options.DisableAccessTokenEncryption = true;
            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = new ClaimsIdentity(
                TokenValidationParameters.DefaultAuthenticationType,
                Claims.Name, Claims.Role);
            // Use the client_id as the subject identifier.
            identity.AddClaim(Claims.Subject, await _applicationManager.GetIdAsync(application),
                Destinations.AccessToken, Destinations.IdentityToken);
            identity.AddClaim(Claims.Name, await _applicationManager.GetDisplayNameAsync(application),
                Destinations.AccessToken, Destinations.IdentityToken);
            // Note: In the original OAuth 2.0 specification, the client credentials grant
            // doesn't return an identity token, which is an OpenID Connect concept.
            //
            // As a non-standardized extension, OpenIddict allows returning an id_token
            // to convey information about the client application when the "openid" scope
            // is granted (i.e specified when calling principal.SetScopes()). When the "openid"
            // scope is not explicitly set, no identity token is returned to the client application.
            // Set the list of scopes granted to the client application in access_token.
            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(context.Request.GetScopes());
            principal.SetResources(await _scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());
            principal.SetAccessTokenLifetime(application.AccessTokenLifetime.HasValue ? TimeSpan.FromSeconds(application.AccessTokenLifetime.Value) : context.Options.AccessTokenLifetime);
            foreach (var claim in principal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim));
            }
            context.SignIn(principal);
            //  context.HandleRequest();
        }
        private IEnumerable<string> GetDestinations(Claim claim)
        {
            // Note: by default, claims are NOT automatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
            // whether they should be included in access tokens, in identity tokens or in both.
            return claim.Type switch
            {
                Claims.Name or
                Claims.Subject
                    => ImmutableArray.Create(Destinations.AccessToken, Destinations.IdentityToken),
                _ => ImmutableArray.Create(Destinations.AccessToken),
            };
        }
    }


    public class OpenIddictServerFactory : IOpenIddictServerFactory
    {
        private readonly ILogger<OpenIddictServerDispatcher> _logger;
        private readonly IOptionsSnapshot<OpenIddictServerOptions> _options;

        public OpenIddictServerFactory(ILogger<OpenIddictServerDispatcher> logger, IOptionsSnapshot<OpenIddictServerOptions> options)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        public ValueTask<OpenIddictServerTransaction> CreateTransactionAsync() => new ValueTask<OpenIddictServerTransaction>(new OpenIddictServerTransaction
        {
            Issuer = _options.Value.Issuer,
            Logger = _logger,
            Options = _options.Value
        });
    }

    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict Entity Framework Core services.
    /// </summary>
    public static class OpenIddictEAVFrameworkeExtensions
    {

        public static OpenIddictBuilder AddOpenIdConnect<TContext,
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
            TOpenIdConnectScope>(this IServiceCollection services)
                where TOpenIdConnectAuthorization : DynamicEntity, IOpenIdConnectAuthorization<TOpenIdConnectClient, TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType>
                where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
                where TAllowedGrantType : DynamicEntity, IAllowedGrantType<TAllowedGrantTypeValue>
                where TAllowedGrantTypeValue : struct, IConvertible
                where TOpenIdConnectClientTypes : struct, IConvertible
                where TOpenIdConnectClientConsentTypes : struct, IConvertible
                where TOpenIdConnectAuthorizationStatus : struct, IConvertible
                where TOpenIdConnectAuthorizationType : struct, IConvertible
                where TOpenIdConnectAuthorizationScope : DynamicEntity, IOpenIdConnectAuthorizationScope<TOpenIdConnectIdentityResource>, new()
                where TOpenIdConnectIdentityResource : DynamicEntity, IOpenIdConnectIdentityResource
                where TOpenIdConnectToken : DynamicEntity, IOpenIdConnectToken<TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectTokenStatus, TOpenIdConnectTokenType>
                where TOpenIdConnectTokenStatus : struct, IConvertible
                where TOpenIdConnectTokenType : struct, IConvertible
              where TOpenIdConnectScopeResource : DynamicEntity, IOpenIdConnectScopeResource<TOpenIdConnectResource, TOpenIdConnectIdentityResource>, new()
            where TOpenIdConnectResource : DynamicEntity, IOpenIdConnectResource
         where TOpenIdConnectScope : DynamicEntity, IOpenIdConnectScope<TOpenIdConnectScopeResource>
            where TContext : DynamicContext
        {
            services.AddScoped<IOpenIddictServerFactory, OpenIddictServerFactory>();

            return services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.UseEAVFramework<TContext,
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
                        TOpenIdConnectScope>();

                }).AddServer(options =>
                {

                    options
                    .SetAuthorizationEndpointUris("/connect/authorize")
                    .SetDeviceEndpointUris("/connect/device")
                    .SetLogoutEndpointUris("/connect/logout")
                    .SetTokenEndpointUris("/connect/token")
                    .SetUserinfoEndpointUris("/connect/userinfo")
                    .SetVerificationEndpointUris("/connect/verify");

                    options.AllowAuthorizationCodeFlow()
                    .AllowDeviceCodeFlow()
                    .AllowPasswordFlow()
                    .AllowRefreshTokenFlow()
                    .AllowClientCredentialsFlow()
                    .AllowHybridFlow();

                    options
                    .AddDevelopmentEncryptionCertificate()
                    .AddDevelopmentSigningCertificate();

                    options.RequireProofKeyForCodeExchange();

                    options.UseAspNetCore()
                    .EnableStatusCodePagesIntegration()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableLogoutEndpointPassthrough()
                    .EnableUserinfoEndpointPassthrough()
                    .EnableVerificationEndpointPassthrough()
                    .DisableTransportSecurityRequirement();

                    options.AddEventHandler<HandleTokenRequestContext>(c => c.UseScopedHandler<TokenHandler<TOpenIdConnectClient, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue>>());
                });

        }

        /// <summary>
        /// Registers the Entity Framework Core stores services in the DI container and
        /// configures OpenIddict to use the Entity Framework Core entities by default.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictEAVFrameworkBuilder"/>.</returns>
        public static OpenIddictEAVFrameworkBuilder UseEAVFramework<
            TContext,
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
            TOpenIdConnectScope>(this OpenIddictCoreBuilder builder)

            where TOpenIdConnectAuthorization : DynamicEntity, IOpenIdConnectAuthorization<TOpenIdConnectClient, TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType>
            where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
            where TAllowedGrantType : DynamicEntity, IAllowedGrantType<TAllowedGrantTypeValue>
            where TAllowedGrantTypeValue : struct, IConvertible
            where TOpenIdConnectClientTypes : struct, IConvertible
            where TOpenIdConnectClientConsentTypes : struct, IConvertible
            where TOpenIdConnectAuthorizationStatus : struct, IConvertible
            where TOpenIdConnectAuthorizationType : struct, IConvertible
            where TOpenIdConnectAuthorizationScope : DynamicEntity, IOpenIdConnectAuthorizationScope<TOpenIdConnectIdentityResource>, new()
            where TOpenIdConnectIdentityResource : DynamicEntity, IOpenIdConnectIdentityResource
            where TOpenIdConnectToken : DynamicEntity, IOpenIdConnectToken<TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectTokenStatus, TOpenIdConnectTokenType>
            where TOpenIdConnectTokenStatus : struct, IConvertible
            where TOpenIdConnectTokenType : struct, IConvertible
              where TOpenIdConnectScopeResource : DynamicEntity, IOpenIdConnectScopeResource<TOpenIdConnectResource, TOpenIdConnectIdentityResource>, new()
            where TOpenIdConnectResource : DynamicEntity, IOpenIdConnectResource
            where TOpenIdConnectScope : DynamicEntity, IOpenIdConnectScope<TOpenIdConnectScopeResource>
            where TContext : DynamicContext
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            // Since Entity Framework Core may be used with databases performing case-insensitive
            // or culture-sensitive comparisons, ensure the additional filtering logic is enforced
            // in case case-sensitive stores were registered before this extension was called.
            builder.Configure(options => options.DisableAdditionalFiltering = false);

            builder.SetDefaultApplicationEntity<TOpenIdConnectClient>()
                   .SetDefaultAuthorizationEntity<TOpenIdConnectAuthorization>()
                   .SetDefaultScopeEntity<TOpenIdConnectScope>()
                   .SetDefaultTokenEntity<TOpenIdConnectToken>();

            builder.ReplaceApplicationStoreResolver<OpenIddictEAVFrameworkStoreResolver>()
                   .ReplaceAuthorizationStoreResolver<OpenIddictEAVFrameworkStoreResolver>()
                   .ReplaceScopeStoreResolver<OpenIddictEAVFrameworkStoreResolver>()
                   .ReplaceTokenStoreResolver<OpenIddictEAVFrameworkStoreResolver>();

            builder.ReplaceApplicationManager<ClientManager<TOpenIdConnectClient, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue>>();
            //builder.Services.TryAddSingleton<OpenIddictEntityFrameworkCoreApplicationStoreResolver.TypeResolutionCache>();
            //builder.Services.TryAddSingleton<OpenIddictEntityFrameworkCoreAuthorizationStoreResolver.TypeResolutionCache>();
            //builder.Services.TryAddSingleton<OpenIddictEntityFrameworkCoreScopeStoreResolver.TypeResolutionCache>();
            //builder.Services.TryAddSingleton<OpenIddictEntityFrameworkCoreTokenStoreResolver.TypeResolutionCache>();

            //builder.Services.TryAddScoped(typeof(OpenIddictEntityFrameworkCoreApplicationStore<,,,,>));
            //builder.Services.TryAddScoped(typeof(OpenIddictEntityFrameworkCoreAuthorizationStore<,,,,>));
            //builder.Services.TryAddScoped(typeof(OpenIddictEntityFrameworkCoreScopeStore<,,>));
            //builder.Services.TryAddScoped(typeof(OpenIddictEntityFrameworkCoreTokenStore<,,,,>));

            builder.Services.TryAddScoped<IOpenIddictAuthorizationStore<TOpenIdConnectAuthorization>,
                OpenIddictEAVFrameworkAuthorizationStore<
                    TContext,
                    TOpenIdConnectClient,
                    TOpenIdConnectAuthorization,
                    TOpenIdConnectToken,
                    TOpenIdConnectTokenStatus,
                    TOpenIdConnectTokenType,
                    TOpenIdConnectAuthorizationStatus,
                    TAllowedGrantType,
                    TOpenIdConnectAuthorizationScope,
                    TOpenIdConnectClientTypes,
                    TOpenIdConnectClientConsentTypes,
                    TAllowedGrantTypeValue,
                    TOpenIdConnectScope,
                    TOpenIdConnectScopeResource,
                    TOpenIdConnectResource,
                    TOpenIdConnectIdentityResource,
                    TOpenIdConnectAuthorizationType>
            >();

            builder.Services.TryAddScoped<IOpenIddictApplicationStore<TOpenIdConnectClient>,
                OpenIddictEAVFrameowrkApplicationStore<
                    TContext,
                    TOpenIdConnectClient,
                    TOpenIdConnectAuthorization,
                    TOpenIdConnectAuthorizationStatus,
                    TOpenIdConnectAuthorizationType,
                    TOpenIdConnectToken,
                    TOpenIdConnectTokenStatus,
                    TOpenIdConnectTokenType,
                    TAllowedGrantType,
                    TOpenIdConnectAuthorizationScope,
                    TOpenIdConnectClientTypes,
                    TOpenIdConnectClientConsentTypes,
                    TAllowedGrantTypeValue,
                    TOpenIdConnectScope, TOpenIdConnectScopeResource, TOpenIdConnectResource, TOpenIdConnectIdentityResource
                    >
            >();

            builder.Services.TryAddScoped<IOpenIddictTokenStore<TOpenIdConnectToken>,
                OpenIddictEAVFrameworkTokenStore<
                    TContext,
                    TOpenIdConnectClient,
                    TOpenIdConnectAuthorization,
                    TOpenIdConnectToken,
                    TOpenIdConnectTokenStatus,
                    TOpenIdConnectTokenType,
                    TOpenIdConnectAuthorizationStatus,
                    TOpenIdConnectAuthorizationType,
                    TAllowedGrantType,
                    TOpenIdConnectAuthorizationScope,
                    TOpenIdConnectClientTypes,
                    TOpenIdConnectClientConsentTypes,
                    TAllowedGrantTypeValue,
                    TOpenIdConnectScope,
                    TOpenIdConnectScopeResource,
                    TOpenIdConnectResource,
                    TOpenIdConnectIdentityResource>
            >();
            builder.Services.TryAddScoped<IOpenIddictScopeStore<TOpenIdConnectScope>,
                OpenIddictEAVFrameowrkScopeStore<
                    TContext,
                    TOpenIdConnectScope,
                    TOpenIdConnectClient,
                    TOpenIdConnectAuthorization,
                    TOpenIdConnectAuthorizationStatus,
                    TOpenIdConnectAuthorizationType,
                    TOpenIdConnectToken,
                    TOpenIdConnectTokenStatus,
                    TOpenIdConnectTokenType,
                    TAllowedGrantType,
                    TOpenIdConnectAuthorizationScope,
                    TOpenIdConnectClientTypes,
                    TOpenIdConnectClientConsentTypes,
                    TAllowedGrantTypeValue,
                    TOpenIdConnectScopeResource,
                    TOpenIdConnectResource,
                    TOpenIdConnectIdentityResource
                >
            >();

            builder.Services.TryAddScoped(typeof(IPrincipalService<TOpenIdConnectAuthorization,
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
            TOpenIdConnectScope>), typeof(DefaultPrincipalService<TOpenIdConnectAuthorization,
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
            TOpenIdConnectScope>));

            return new OpenIddictEAVFrameworkBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the Entity Framework Core stores services in the DI container and
        /// configures OpenIddict to use the Entity Framework Core entities by default.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the Entity Framework Core services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
        public static OpenIddictCoreBuilder UseEAVFramework<TContext,
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
            TOpenIdConnectScope>(
            this OpenIddictCoreBuilder builder, Action<OpenIddictEAVFrameworkBuilder> configuration)
            where TOpenIdConnectAuthorization : DynamicEntity, IOpenIdConnectAuthorization<TOpenIdConnectClient,  TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType>
            where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
            where TAllowedGrantType : DynamicEntity, IAllowedGrantType<TAllowedGrantTypeValue>
            where TAllowedGrantTypeValue : struct, IConvertible
            where TOpenIdConnectClientTypes : struct, IConvertible
            where TOpenIdConnectClientConsentTypes : struct, IConvertible
            where TOpenIdConnectAuthorizationStatus : struct, IConvertible
            where TOpenIdConnectAuthorizationType : struct, IConvertible
            where TOpenIdConnectAuthorizationScope : DynamicEntity, IOpenIdConnectAuthorizationScope<TOpenIdConnectIdentityResource>, new()
            where TOpenIdConnectIdentityResource : DynamicEntity, IOpenIdConnectIdentityResource
            where TOpenIdConnectToken : DynamicEntity, IOpenIdConnectToken<TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectTokenStatus, TOpenIdConnectTokenType>
            where TOpenIdConnectTokenStatus : struct, IConvertible
            where TOpenIdConnectTokenType : struct, IConvertible
            where TOpenIdConnectScopeResource : DynamicEntity, IOpenIdConnectScopeResource<TOpenIdConnectResource, TOpenIdConnectIdentityResource>, new()
            where TOpenIdConnectResource : DynamicEntity, IOpenIdConnectResource
 where TOpenIdConnectScope : DynamicEntity, IOpenIdConnectScope<TOpenIdConnectScopeResource>
            where TContext : DynamicContext

        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            configuration(builder.UseEAVFramework<TContext,
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
                TOpenIdConnectScope>());

            return builder;
        }
    }


}