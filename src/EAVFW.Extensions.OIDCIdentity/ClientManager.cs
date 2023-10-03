

using EAVFramework;
using EAVFramework.Endpoints;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;



namespace EAVFW.Extensions.OIDCIdentity
{
    public interface IEAVApplicationManager : IOpenIddictApplicationManager
    {

    }
    public class EAVApplicationManager<TContext,TOpenIdConnectClient, TOpenIdConnectSecret, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue> 
        : OpenIddictApplicationManager<TOpenIdConnectClient>
        where TContext : DynamicContext
        where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
        where TOpenIdConnectSecret : DynamicEntity, IOpenIdConnectSecret
        where TOpenIdConnectClientTypes : struct, IConvertible
        where TOpenIdConnectClientConsentTypes : struct, IConvertible
        where TAllowedGrantTypeValue : struct, IConvertible
        where TAllowedGrantType : DynamicEntity, IAllowedGrantType<TAllowedGrantTypeValue>
    {
        private readonly EAVDBContext<TContext> _context;

        public EAVApplicationManager(EAVDBContext<TContext> context, IOpenIddictApplicationCache<TOpenIdConnectClient> cache, ILogger<OpenIddictApplicationManager<TOpenIdConnectClient>> logger, IOptionsMonitor<OpenIddictCoreOptions> options, IOpenIddictApplicationStoreResolver resolver) : base(cache, logger, options, resolver)
        {
            this._context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public override async ValueTask<bool> ValidateClientSecretAsync(TOpenIdConnectClient application, string secret, CancellationToken cancellationToken = default)
        {

            var secrets = await _context.Set<TOpenIdConnectSecret>().Where(s => s.ClientId == application.Id && (s.Expiration == null || s.Expiration > DateTime.UtcNow))
                .Select(c => c.Value).ToListAsync();
            foreach (var value in secrets)
            {
                if (await base.ValidateClientSecretAsync(secret, value, cancellationToken))
                    return true;
            }

            return await base.ValidateClientSecretAsync(application, secret, cancellationToken);
        }

        public new ValueTask<string> ObfuscateClientSecretAsync(string secret, CancellationToken cancellationToken = default)
        {
            return base.ObfuscateClientSecretAsync(secret, cancellationToken);
        }

        
        protected override ValueTask<bool> ValidateClientSecretAsync(string secret, string comparand, CancellationToken cancellationToken = default)
        {
            //TODO Validate this implementation
           // return new ValueTask<bool>(true);
            return base.ValidateClientSecretAsync(secret, comparand, cancellationToken);
        }
    }


}