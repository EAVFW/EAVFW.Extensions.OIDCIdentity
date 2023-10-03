using EAVFramework;
using EAVFramework.Plugins;
using EAVFramework.Validation;
using OpenIddict.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace EAVFW.Extensions.OIDCIdentity.Plugins
{



    [PluginRegistration(EntityPluginExecution.PreOperation, EntityPluginOperation.Create)]
    public class ObfuscateSecretPlugin<TContext, TClientManager,
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
        TOpenIdConnectScope> : IPlugin<TContext, TOpenIdConnectSecret> , IPluginRegistration
            where TClientManager : EAVApplicationManager<TContext, TOpenIdConnectClient, TOpenIdConnectSecret, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue>
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
        private readonly TClientManager _applicationManager;
        

        public ObfuscateSecretPlugin(TClientManager applicationManager)
        {
            _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));
           
        }

        public async Task Execute(PluginContext<TContext, TOpenIdConnectSecret> context)
        {
            context.Input.Value = await _applicationManager.ObfuscateClientSecretAsync(context.Input.Value);

        }
    }
    [PluginRegistration(EntityPluginExecution.PreValidate, EntityPluginOperation.Create)]
    public class ValidateCreateApplicationPlugin<TContext, TClientManager,
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
        TOpenIdConnectScope> : IPlugin<TContext, TOpenIdConnectClient>, IPluginRegistration
            where TClientManager : EAVApplicationManager<TContext, TOpenIdConnectClient, TOpenIdConnectSecret, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue>
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
        private readonly TClientManager _applicationManager;


        public ValidateCreateApplicationPlugin(TClientManager applicationManager)
        {
            _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

        }

        public async Task Execute(PluginContext<TContext, TOpenIdConnectClient> context)
        {
            var application = context.Input;
            var cancellationToken = CancellationToken.None;

            var secret = application.ClientSecret;
            application.ClientSecret = null;

            var obf = await _applicationManager.ObfuscateClientSecretAsync(secret);
            application.ClientSecret = obf;
            var validationResult = await _applicationManager.ValidateAsync(application, cancellationToken).ToListAsync();

            if (validationResult.Any())
            {
                foreach (var err in validationResult)
                    context.AddValidationError(new ValidationError { Error = err.ErrorMessage, EntityCollectionSchemaName = "OpenIdConnectClients" });

            }




        }
    }

     
}
