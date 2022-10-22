using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using System;
using System.Threading.Tasks;



namespace EAVFW.Extensions.OIDCIdentity
{
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


}