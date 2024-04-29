using EAVFramework;
using EAVFW.Extensions.OIDCIdentity.Plugins;
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
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;



namespace EAVFW.Extensions.OIDCIdentity
{
    public class EAVOpenIdConnectOptions
    {
        public bool UseDevelopmentCertificates { get; set; }
        public string SigningCertificateThumbprint { get; set; }
        public string EncryptionCertificateThumbprint { get; set; }
        public string Authority { get; set; }
    }
    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict Entity Framework Core services.
    /// </summary>
    public static class OpenIddictEAVFrameworkeExtensions
    {
        public static X509Certificate2 TryLoadCertificateInAzureLinuxContainerIfFound(string CertificateThumbprint)
        {
            if (string.IsNullOrEmpty(CertificateThumbprint))
                return null;

            string finalPath = $"/var/ssl/private/{CertificateThumbprint}.p12";
            var bytes2 = File.ReadAllBytes(finalPath);
            var cert = new X509Certificate2(bytes2);

            return cert;

        }
        public static OpenIddictBuilder AddOpenIdConnect<TContext,
          TOpenIdConnectAuthorization,
          TOpenIdConnectClient,
          TOpenIdConnectSecret,
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
          TOpenIdConnectScope>(this IServiceCollection services, EAVOpenIdConnectOptions options)
              where TOpenIdConnectAuthorization : DynamicEntity, IOpenIdConnectAuthorization<TOpenIdConnectClient, TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType>
              where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
              where TOpenIdConnectSecret : DynamicEntity, IOpenIdConnectSecret
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
            return services.AddOpenIdConnect<TContext, EAVApplicationManager<TContext,TOpenIdConnectClient,TOpenIdConnectSecret, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue>, TOpenIdConnectAuthorization,
          TOpenIdConnectClient,
          TOpenIdConnectSecret,
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
          TOpenIdConnectScope>(options);
        }
        public static OpenIddictBuilder AddOpenIdConnect<TContext, TClientManager,
        TOpenIdConnectAuthorization,
        TOpenIdConnectClient,
        TOpenIdConnectSecret,
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
        TOpenIdConnectScope>(this IServiceCollection services, EAVOpenIdConnectOptions eavoptions)
            where TClientManager : EAVApplicationManager<TContext,TOpenIdConnectClient, TOpenIdConnectSecret, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue>
            where TOpenIdConnectAuthorization : DynamicEntity, IOpenIdConnectAuthorization<TOpenIdConnectClient, TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType>
            where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
            where TOpenIdConnectSecret : DynamicEntity, IOpenIdConnectSecret
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
            services.AddPlugin<ValidateCreateApplicationPlugin<TContext, TClientManager,
                    TOpenIdConnectAuthorization,
                    TOpenIdConnectClient,
                    TOpenIdConnectSecret,
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
                    TOpenIdConnectScope>>();

            services.AddPlugin<ObfuscateSecretPlugin<TContext, TClientManager,
                   TOpenIdConnectAuthorization,
                   TOpenIdConnectClient,
                   TOpenIdConnectSecret,
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
                   TOpenIdConnectScope>>();


            var b = services.AddOpenIddict()
                 .AddCore(options =>
                 {

                     options.UseEAVFramework<TContext, TClientManager,
                         TOpenIdConnectAuthorization,
                         TOpenIdConnectClient,
                         TOpenIdConnectSecret,
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

                     if (eavoptions.UseDevelopmentCertificates)
                     {

                         options
                         .AddDevelopmentEncryptionCertificate()
                         .AddDevelopmentSigningCertificate();
                     }

                     if (!string.IsNullOrEmpty(eavoptions.EncryptionCertificateThumbprint))
                     {
                         if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                         {
                             options.AddEncryptionCertificate(TryLoadCertificateInAzureLinuxContainerIfFound(eavoptions.EncryptionCertificateThumbprint));
                         }
                         else
                             options.AddEncryptionCertificate(eavoptions.EncryptionCertificateThumbprint, System.Security.Cryptography.X509Certificates.StoreName.My, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
                     }
                     if (!string.IsNullOrEmpty(eavoptions.SigningCertificateThumbprint))
                     {
                         if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                         {
                             options.AddSigningCertificate(TryLoadCertificateInAzureLinuxContainerIfFound(eavoptions.SigningCertificateThumbprint));
                         }
                         else
                             options.AddSigningCertificate(eavoptions.SigningCertificateThumbprint, System.Security.Cryptography.X509Certificates.StoreName.My, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
                     }

                     if (!string.IsNullOrEmpty(eavoptions.Authority))
                         options.SetIssuer(eavoptions.Authority);
                    
                     options.RequireProofKeyForCodeExchange();

                     options.UseAspNetCore()
                     .EnableStatusCodePagesIntegration()
                     .EnableAuthorizationEndpointPassthrough()
                     .EnableLogoutEndpointPassthrough()
                     .EnableUserinfoEndpointPassthrough()
                     .EnableVerificationEndpointPassthrough()
                     .DisableTransportSecurityRequirement();

                     options.AddEventHandler<HandleTokenRequestContext>(c => c.UseScopedHandler<TokenHandler<TContext,TClientManager, TOpenIdConnectClient, TOpenIdConnectSecret, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue>>());
                 });
            services.AddScoped<IOpenIddictServerFactory, OpenIddictServerFactory>();

            return b;

        }



        public static OpenIddictEAVFrameworkBuilder UseEAVFramework<
            TContext,
            TOpenIdConnectAuthorization,
            TOpenIdConnectClient,
            TOpenIdConnectSecret,
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
            where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
            where TOpenIdConnectSecret : DynamicEntity, IOpenIdConnectSecret
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
            return builder.UseEAVFramework<TContext, EAVApplicationManager<TContext,TOpenIdConnectClient,TOpenIdConnectSecret, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue>, TOpenIdConnectAuthorization,
            TOpenIdConnectClient,
            TOpenIdConnectSecret,
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
        TClientManager,
        TOpenIdConnectAuthorization,
        TOpenIdConnectClient,
        TOpenIdConnectSecret,
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
        where TClientManager : EAVApplicationManager<TContext,TOpenIdConnectClient,TOpenIdConnectSecret, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue>
        where TOpenIdConnectAuthorization : DynamicEntity, IOpenIdConnectAuthorization<TOpenIdConnectClient, TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType>
        where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
        where TOpenIdConnectSecret : DynamicEntity, IOpenIdConnectSecret
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

            builder.ReplaceApplicationManager<TClientManager>();
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
            TOpenIdConnectSecret,
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
            where TOpenIdConnectAuthorization : DynamicEntity, IOpenIdConnectAuthorization<TOpenIdConnectClient, TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType>
            where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
            where TOpenIdConnectSecret : DynamicEntity, IOpenIdConnectSecret
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
                TOpenIdConnectSecret,
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