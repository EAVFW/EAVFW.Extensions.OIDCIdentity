using EAVFramework;
using EAVFramework.Shared;
using System;
using System.Collections.Generic;

namespace EAVFW.Extensions.OIDCIdentity
{
    
 
    [EntityInterface(EntityKey = "OpenId Connect Authorization")]
   // [ConstraintMapping(EntityKey = "Allowed Grant Type", AttributeKey = "Allowed Grant Type Value", ConstraintName = nameof(TAllowedGrantTypeValue))]
    [ConstraintMapping(AttributeKey = "Type", ConstraintName = nameof(TOpenIdConnectAuthorizationType))]
    [ConstraintMapping(AttributeKey = "Status", ConstraintName = nameof(TOpenIdConnectAuthorizationStatus))]
    [ConstraintMapping(EntityKey = "OpenId Connect Client", ConstraintName = nameof(TOpenIdConnectClient))]
   // [ConstraintMapping(EntityKey = "OpenId Connect Token", ConstraintName = nameof(TOpenIdConnectToken))]
 //   [ConstraintMapping(EntityKey = "OpenId Connect Authorization Scope", ConstraintName = nameof(TOpenIdConnectAuthorizationScope))]
    public interface IOpenIdConnectAuthorization<TOpenIdConnectClient,TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType>
        where TOpenIdConnectClient : DynamicEntity
       // where TOpenIdConnectToken : DynamicEntity
       // where TOpenIdConnectAuthorizationScope : DynamicEntity
        where TOpenIdConnectAuthorizationStatus : struct, IConvertible
        where TOpenIdConnectAuthorizationType : struct, IConvertible

        //<TOpenIdConnectClient, TAllowedGrantType,TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType, TOpenIdConnectAuthorizationScope, TOpenIdConnectAuthorization, 
        //TOpenIdConnectToken, TOpenIdConnectTokenStatus, TOpenIdConnectTokenType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue, TOpenIdConnectIdentityResource>
        //where TOpenIdConnectAuthorization : DynamicEntity, IOpenIdConnectAuthorization<TOpenIdConnectClient, TAllowedGrantType, TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType, TOpenIdConnectAuthorizationScope, 
        //    TOpenIdConnectAuthorization, TOpenIdConnectToken,TOpenIdConnectTokenStatus, TOpenIdConnectTokenType,TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue, TOpenIdConnectIdentityResource>
        //where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue>
        //
        //where TAllowedGrantType : DynamicEntity, IAllowedGrantType<TAllowedGrantTypeValue>
        //where TOpenIdConnectAuthorizationScope : DynamicEntity, IOpenIdConnectAuthorizationScope<TOpenIdConnectIdentityResource>
        //where TOpenIdConnectToken : DynamicEntity, IOpenIdConnectToken<TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectTokenStatus, TOpenIdConnectTokenType,
        //    TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType,TAllowedGrantType, TOpenIdConnectAuthorizationScope, TOpenIdConnectToken, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue, TOpenIdConnectIdentityResource>
        //where TOpenIdConnectTokenStatus : struct, IConvertible
        //where TOpenIdConnectTokenType : struct, IConvertible
        //where TOpenIdConnectClientTypes : struct, IConvertible
        //where TOpenIdConnectClientConsentTypes : struct, IConvertible
        //where TAllowedGrantTypeValue : struct, IConvertible
        //where TOpenIdConnectIdentityResource : DynamicEntity, IOpenIdConnectIdentityResource
        //where TOpenIdConnectAuthorizationType : struct, IConvertible
    {
        public TOpenIdConnectAuthorizationStatus? Status { get; set; }
        public TOpenIdConnectAuthorizationType? Type { get; set; }

        public Guid Id { get; set; }
        public Guid? ClientId { get; set; }
        public Guid? SubjectId { get; set; }
        public TOpenIdConnectClient Client { get; set; }
        public DateTime? CreatedOn { get; set; }    
        //public ICollection<TOpenIdConnectToken> OpenIdConnectTokens { get; set; }
        //public ICollection<TOpenIdConnectAuthorizationScope> OpenIdConnectAuthorizationScopes { get; set; }

        public string Properties { get; set; }
    }

}