using EAVFramework;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace EAVFW.Extensions.OIDCIdentity
{
        public interface IPrincipalService<
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
            >
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
            where TOpenIdConnectScopeResource : DynamicEntity, IOpenIdConnectScopeResource<TOpenIdConnectResource, TOpenIdConnectIdentityResource>
            where TOpenIdConnectResource : DynamicEntity, IOpenIdConnectResource
        where TOpenIdConnectScope : DynamicEntity, IOpenIdConnectScope<TOpenIdConnectScopeResource>
    {
        ValueTask<ClaimsPrincipal> CreatePrincipal(string subjectid);
        ValueTask<ClaimsPrincipal> CreatePrincipalForToken(string creatingClientId);
        ValueTask<ClaimsPrincipal> CreatePrincipalForDeleteToken();
        ValueTask<ClaimsPrincipal> CreatePrincipalForPruneToken();
        ValueTask<ClaimsPrincipal> CreatePrincipalForTokenUpdate();
        ValueTask<ClaimsPrincipal> CreatePrincipalForClient();
        ValueTask<ClaimsPrincipal> CreatePrincipalForDeleteClient();
        ValueTask<ClaimsPrincipal> CreatePrincipalForUpdateClient();
        ValueTask<ClaimsPrincipal> CreatePrincipalForPruneAuthorization();
        ValueTask<ClaimsPrincipal> UpdatePrincipalFor(TOpenIdConnectAuthorization authorization);
        ValueTask<ClaimsPrincipal> CreatePrincipalForScope(TOpenIdConnectScope scope);
        ValueTask<ClaimsPrincipal> CreatePrincipalForDeleteScope(TOpenIdConnectScope scope);

        ValueTask<ClaimsPrincipal> UpdatePrincipalFor(TOpenIdConnectScope scope);

        ValueTask<ClaimsPrincipal> CreatePrincipalFor(TOpenIdConnectAuthorization authorization);
        ValueTask<ClaimsPrincipal> DeletePrincipalFor(TOpenIdConnectAuthorization authorization);
           
    }
    public class DefaultPrincipalService<
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
        >
        : IPrincipalService<
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
        >
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
            where TOpenIdConnectScopeResource : DynamicEntity, IOpenIdConnectScopeResource<TOpenIdConnectResource, TOpenIdConnectIdentityResource>
            where TOpenIdConnectResource : DynamicEntity, IOpenIdConnectResource
       where TOpenIdConnectScope : DynamicEntity, IOpenIdConnectScope<TOpenIdConnectScopeResource>
    {
        protected readonly IHttpContextAccessor httpContextAccessor;

        public DefaultPrincipalService(IHttpContextAccessor httpContextAccessor)
        {
            this.httpContextAccessor = httpContextAccessor;
        }
        public ValueTask<ClaimsPrincipal> CreatePrincipal(string subjectid)
        {
            return new ValueTask<ClaimsPrincipal>(new ClaimsPrincipal(new ClaimsIdentity(new Claim[] {
                                   new Claim(Claims.Subject,subjectid)
                                }, EAVFramework.Constants.DefaultCookieAuthenticationScheme)));
        }
        protected ValueTask<ClaimsPrincipal> Create(ClaimsPrincipal principal)
        {
            return new ValueTask<ClaimsPrincipal>(principal);
        }
        protected ValueTask<ClaimsPrincipal> CreateFromHttpContextUser()
        {
            return Create(httpContextAccessor.HttpContext.User);
        }
        public ValueTask<ClaimsPrincipal> CreatePrincipalForDeleteToken()
        {
            return CreateFromHttpContextUser();
        }

        public ValueTask<ClaimsPrincipal> CreatePrincipalForToken(string creatingClientId) => CreatePrincipal(creatingClientId);

        public ValueTask<ClaimsPrincipal> CreatePrincipalForPruneToken()
        {
            return CreateFromHttpContextUser();
        }

        public ValueTask<ClaimsPrincipal> CreatePrincipalForTokenUpdate()
        {
            return CreateFromHttpContextUser();
        }

        public ValueTask<ClaimsPrincipal> CreatePrincipalForClient()
        {
            return CreateFromHttpContextUser();
        }

        public ValueTask<ClaimsPrincipal> CreatePrincipalForDeleteClient()
        {
            return CreateFromHttpContextUser();
        }

        public ValueTask<ClaimsPrincipal> CreatePrincipalForUpdateClient()
        {
            return CreateFromHttpContextUser();
        }

        public ValueTask<ClaimsPrincipal> CreatePrincipalForPruneAuthorization()
        {
            return CreateFromHttpContextUser();
        }

        public ValueTask<ClaimsPrincipal> UpdatePrincipalFor(TOpenIdConnectAuthorization authorization)
        {
            return CreateFromHttpContextUser();
        }

        public ValueTask<ClaimsPrincipal> CreatePrincipalForScope(TOpenIdConnectScope scope)
        {
            return CreateFromHttpContextUser();
        }

        public ValueTask<ClaimsPrincipal> CreatePrincipalForDeleteScope(TOpenIdConnectScope scope)
        {
            return CreateFromHttpContextUser();
        }

        public ValueTask<ClaimsPrincipal> UpdatePrincipalFor(TOpenIdConnectScope scope)
        {
            return CreateFromHttpContextUser();
        }

        public ValueTask<ClaimsPrincipal> CreatePrincipalFor(TOpenIdConnectAuthorization authorization)
        {
            return CreateFromHttpContextUser();
        }

        public ValueTask<ClaimsPrincipal> DeletePrincipalFor(TOpenIdConnectAuthorization authorization)
        {
            return CreateFromHttpContextUser();
        }
    }
}
