

using EAVFramework;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using System;
using System.Threading;
using System.Threading.Tasks;

#nullable enable

namespace EAVFW.Extensions.OIDCIdentity
{
    public class ClientManager<TOpenIdConnectClient, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue> : OpenIddictApplicationManager<TOpenIdConnectClient>
        where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
        where TOpenIdConnectClientTypes : struct, IConvertible
        where TOpenIdConnectClientConsentTypes : struct, IConvertible
        where TAllowedGrantTypeValue : struct, IConvertible
        where TAllowedGrantType : DynamicEntity, IAllowedGrantType<TAllowedGrantTypeValue>
    {
        public ClientManager(IOpenIddictApplicationCache<TOpenIdConnectClient> cache, ILogger<OpenIddictApplicationManager<TOpenIdConnectClient>> logger, IOptionsMonitor<OpenIddictCoreOptions> options, IOpenIddictApplicationStoreResolver resolver) : base(cache, logger, options, resolver)
        {
        }

        public new ValueTask<string> ObfuscateClientSecretAsync(string secret, CancellationToken cancellationToken = default)
        {
            return base.ObfuscateClientSecretAsync(secret, cancellationToken);
        }

        public override ValueTask<bool> ValidateClientSecretAsync(TOpenIdConnectClient application, string secret, CancellationToken cancellationToken = default)
        {
            //TODO Validate this implementation
            return new ValueTask<bool>(true);
            return base.ValidateClientSecretAsync(application, secret, cancellationToken);
        }
        protected override ValueTask<bool> ValidateClientSecretAsync(string secret, string comparand, CancellationToken cancellationToken = default)
        {
            //TODO Validate this implementation
            return new ValueTask<bool>(true);
            return base.ValidateClientSecretAsync(secret, comparand, cancellationToken);
        }
    }


}