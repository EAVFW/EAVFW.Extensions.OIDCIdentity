using EAVFramework;
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
    public class TokenHandler<TClientManager, TOpenIdConnectClient, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue> : IOpenIddictServerHandler<HandleTokenRequestContext>
        where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
        where TOpenIdConnectClientTypes : struct, IConvertible
        where TOpenIdConnectClientConsentTypes : struct, IConvertible
        where TAllowedGrantTypeValue : struct, IConvertible
        where TAllowedGrantType : DynamicEntity, IAllowedGrantType<TAllowedGrantTypeValue>
        where TClientManager : EAVApplicationManager<TOpenIdConnectClient, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue>
    {
        private readonly EAVApplicationManager<TOpenIdConnectClient, TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue> _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        public TokenHandler(TClientManager applicationManager, IOpenIddictScopeManager scopeManager)
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


}