using Azure.Core;
using EAVFramework;
using EAVFramework.Configuration;
using EAVFramework.Plugins;
using EAVFW.Extensions.OIDCIdentity.Plugins;
using EAVFW.Extensions.OIDCIdentity.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.Server;
using Sprache;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;



namespace EAVFW.Extensions.OIDCIdentity
{
    public class EAVOpenIdConnectKeyVaultOptions
    {
        public string ManagedIdentityUserId { get; set; }
        public string VaultName { get; set; }
        public string SigningCertificateName { get; set; }
        public string EncryptionCertificateName { get; set; }
        public TokenCredential Token { get; set; }
    }
    public class EAVOpenIdConnectOptions
    {
        public bool UseDevelopmentCertificates { get; set; }
        public string SigningCertificateThumbprint { get; set; }
        public string EncryptionCertificateThumbprint { get; set; }
        public string Authority { get; set; }
        public EAVOpenIdConnectKeyVaultOptions KeyVaultCertificates { get; set; }

        public Action<OpenIddictServerBuilder> OnConfigureOpenIddict { get; set; }
    }


    /// <summary>
    /// Represents a service responsible for creating transactions.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public sealed class MultiTenantOpenIddictServerFactory : IOpenIddictServerFactory
    {
        private readonly ILogger _logger;
        private readonly IOptionsSnapshot<OpenIddictServerOptions> _options;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictServerDispatcher"/> class.
        /// </summary>
        public MultiTenantOpenIddictServerFactory(
            ILogger<OpenIddictServerDispatcher> logger,
            IOptionsSnapshot<OpenIddictServerOptions> options)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <inheritdoc/>
        public ValueTask<OpenIddictServerTransaction> CreateTransactionAsync()
        {

            return new(new OpenIddictServerTransaction
            {
                Logger = _logger,
                Options = _options.Value
            });
        }
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

        public static OpenIddictBuilder AddOpenIdConnect<TContext>(this IServiceCollection services)
            where TContext : DynamicContext
        {
            services.AddDynamicContextPlugin<TContext>(typeof(ValidateCreateApplicationPlugin<,,,,,,,,,,,,,,,,,,>));
            services.AddDynamicContextPlugin<TContext>(typeof(ObfuscateSecretPlugin<,,,,,,,,,,,,,,,,,,>));
            services.AddScoped(typeof(EAVApplicationManager<,,,,,,>));
            services.AddScoped< IOpenIddictApplicationManager>( sp => sp.GetDynamicService<TContext>( typeof(EAVApplicationManager<,,,,,,>)) as IOpenIddictApplicationManager);
            
            var b = services.AddOpenIddict()
               .AddCore(options =>
               {
                   ConfigureCoreOIDCBuilder<DynamicOpenIddictEAVFrameworkStoreResolver<TContext>>(options);
                   
                  // options.(typeof(), sp => typeof(EAVApplicationManager<TContext, TOpenIdConnectClient, TOpenIdConnectSecret, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue>))

               });
            b.AddEAVOIDCServer();
            b.AddServer(bb =>
            {
                bb.AddDevelopmentEncryptionCertificate();
                bb.AddDevelopmentSigningCertificate();

                bb.Services.TryAddScoped(typeof(OpenIddictEAVFrameworkAuthorizationStore<,,,,,,,,,,,,,,,,>));
                bb.Services.TryAddScoped(typeof(OpenIddictEAVFrameowrkApplicationStore<,,,,,,,,,,,,,,,,>));
                bb.Services.TryAddScoped(typeof(OpenIddictEAVFrameworkTokenStore<,,,,,,,,,,,,,,,,>));
                bb.Services.TryAddScoped(typeof(OpenIddictEAVFrameowrkScopeStore<,,,,,,,,,,,,,,,,>));

                bb.AddEventHandler<HandleTokenRequestContext>(c =>
                   c.UseScopedHandler<IOpenIddictServerHandler<HandleTokenRequestContext>>(sp => sp.GetDynamicService<TContext>(typeof(TokenHandler<,,,,,,,>))));


            });

            services.AddScoped<IOpenIddictServerFactory, MultiTenantOpenIddictServerFactory>();


            return b;    
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

                 });

            b.AddEAVOIDCServer(eavoptions);

            

            b.AddServer(builder =>
            {
              //  builder.AddEventHandler(new OpenIddictServerHandlerDescriptor() { });
                builder.AddEventHandler<HandleTokenRequestContext>(c => 
                    c.UseScopedHandler<TokenHandler<TContext, TClientManager, TOpenIdConnectClient, TOpenIdConnectSecret, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue>>());

            });
            services.AddScoped<IOpenIddictServerFactory, OpenIddictServerFactory>();

            return b;

        }

        private static void AddEAVOIDCServer(this OpenIddictBuilder b,EAVOpenIdConnectOptions eavoptions=null)
        {
            b.AddServer(options =>
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

                if (eavoptions?.UseDevelopmentCertificates??false)
                {

                    options
                    .AddDevelopmentEncryptionCertificate()
                    .AddDevelopmentSigningCertificate();
                }
                
                if (!string.IsNullOrEmpty(eavoptions?.EncryptionCertificateThumbprint))
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    {
                        options.AddEncryptionCertificate(TryLoadCertificateInAzureLinuxContainerIfFound(eavoptions.EncryptionCertificateThumbprint));
                    }
                    else
                        options.AddEncryptionCertificate(eavoptions.EncryptionCertificateThumbprint, System.Security.Cryptography.X509Certificates.StoreName.My, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
                }

                if (!string.IsNullOrEmpty(eavoptions?.SigningCertificateThumbprint))
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    {
                        options.AddSigningCertificate(TryLoadCertificateInAzureLinuxContainerIfFound(eavoptions.SigningCertificateThumbprint));
                    }
                    else
                        options.AddSigningCertificate(eavoptions.SigningCertificateThumbprint, System.Security.Cryptography.X509Certificates.StoreName.My, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
                }

                if (!string.IsNullOrEmpty(eavoptions?.KeyVaultCertificates?.VaultName))
                {
                    foreach (var signingCertificate in
                       KeyvaultCertificateProvider.LoadCertificateVerisons(
                           eavoptions.KeyVaultCertificates?.ManagedIdentityUserId,
                           eavoptions.KeyVaultCertificates.VaultName,
                           eavoptions.KeyVaultCertificates.SigningCertificateName, eavoptions.KeyVaultCertificates.Token))
                    {
                        options.AddSigningCertificate(signingCertificate);
                    }

                    foreach (var encryptionCertificate in
                     KeyvaultCertificateProvider.LoadCertificateVerisons(
                         eavoptions.KeyVaultCertificates?.ManagedIdentityUserId,
                         eavoptions.KeyVaultCertificates.VaultName,
                         eavoptions.KeyVaultCertificates.EncryptionCertificateName, eavoptions.KeyVaultCertificates.Token))
                    {
                        options.AddEncryptionCertificate(encryptionCertificate);
                    }
                }
               

                if (!string.IsNullOrEmpty(eavoptions?.Authority))
                {

                    options.SetIssuer(eavoptions.Authority);
                    //options.SetCryptographyEndpointUris($"{eavoptions.Authority.Trim('/')}/.well-known/jwks");
                    //options.SetAuthorizationEndpointUris($"{eavoptions.Authority.Trim('/')}/connect/authorize");
                    //options.SetTokenEndpointUris($"{eavoptions.Authority.Trim('/')}/connect/token");
                    //options.SetUserinfoEndpointUris($"{eavoptions.Authority.Trim('/')}/connect/userinfo");
                    //options.SetLogoutEndpointUris($"{eavoptions.Authority.Trim('/')}/connect/logout");
                    //options.SetDeviceEndpointUris($"{eavoptions.Authority.Trim('/')}/connect/device");

                }


                options.RequireProofKeyForCodeExchange();

                options.UseAspNetCore()
                .EnableStatusCodePagesIntegration()
                .EnableAuthorizationEndpointPassthrough()
                .EnableLogoutEndpointPassthrough()
                .EnableUserinfoEndpointPassthrough()
                .EnableVerificationEndpointPassthrough()
                .DisableTransportSecurityRequirement();

                eavoptions?.OnConfigureOpenIddict?.Invoke(options);

            });
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

            builder.SetDefaultApplicationEntity<TOpenIdConnectClient>()
                   .SetDefaultAuthorizationEntity<TOpenIdConnectAuthorization>()
                   .SetDefaultScopeEntity<TOpenIdConnectScope>()
                   .SetDefaultTokenEntity<TOpenIdConnectToken>();

            ConfigureCoreOIDCBuilder<OpenIddictEAVFrameworkStoreResolver>(builder);

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

        private static void ConfigureCoreOIDCBuilder<TStoreResolver>(OpenIddictCoreBuilder builder)
            where TStoreResolver: IStoreResolver
        {
            builder.Configure(options => options.DisableAdditionalFiltering = false);

           builder.Services.TryAddScoped(typeof(IPrincipalService<,,,,,,,,,,,,,,,>), typeof(DefaultPrincipalService<,,,,,,,,,,,,,,,>));

            
            builder.ReplaceApplicationStoreResolver<TStoreResolver>()
                   .ReplaceAuthorizationStoreResolver<TStoreResolver>()
                   .ReplaceScopeStoreResolver<TStoreResolver>()
                   .ReplaceTokenStoreResolver<TStoreResolver>();
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