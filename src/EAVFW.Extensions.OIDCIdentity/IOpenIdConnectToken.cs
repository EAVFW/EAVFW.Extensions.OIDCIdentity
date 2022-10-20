using EAVFramework;
using EAVFramework.Shared;
using System;

namespace EAVFW.Extensions.OIDCIdentity
{
    [EntityInterface(EntityKey = "OpenId Connect Token")]
    [ConstraintMapping(AttributeKey = "Status", ConstraintName = nameof(TOpenIdConnectTokenStatus))]
    [ConstraintMapping( AttributeKey = "Type", ConstraintName = nameof(TOpenIdConnectTokenType))]
    [ConstraintMapping(EntityKey = "OpenId Connect Client", ConstraintName = nameof(TOpenIdConnectClient))]
    [ConstraintMapping(EntityKey = "OpenId Connect Authorization", ConstraintName = nameof(TOpenIdConnectAuthorization))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Authorization", AttributeKey = "Status", ConstraintName = "TOpenIdConnectAuthorizationStatus")]
    //[ConstraintMapping(EntityKey = "OpenId Connect Client", AttributeKey = "Type", ConstraintName = "TOpenIdConnectClientTypes")]
    //[ConstraintMapping(EntityKey = "OpenId Connect Client", AttributeKey = "Consent Type", ConstraintName = "TOpenIdConnectClientConsentTypes")]
    //[ConstraintMapping(EntityKey = "Allowed Grant Type", AttributeKey = "Allowed Grant Type Value", ConstraintName = nameof(TAllowedGrantTypeValue))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Authorization", AttributeKey = "Type", ConstraintName = "TOpenIdConnectAuthorizationType")]
    ////[EntityChoice(AttributeKey= "Status")]
    //[GenericTypeArgument(ArgumentName = "TOpenIdConnectClient", ManifestKey = "OpenId Connect Client")]
    public interface IOpenIdConnectToken<TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectTokenStatus, TOpenIdConnectTokenType>
        where TOpenIdConnectClient : DynamicEntity
        where TOpenIdConnectAuthorization :DynamicEntity
        where TOpenIdConnectTokenStatus: struct, IConvertible
        where TOpenIdConnectTokenType : struct, IConvertible
        //<TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectTokenStatus, TOpenIdConnectTokenType, [EntityChoice(AttributeKey = "Status")] TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType,
        //TAllowedGrantType, TOpenIdConnectAuthorizationScope, TOpenIdConnectToken, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue, TOpenIdConnectIdentityResource>
        //where TOpenIdConnectToken : DynamicEntity, IOpenIdConnectToken<TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectTokenStatus, TOpenIdConnectTokenType,
        //    TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType, TAllowedGrantType, TOpenIdConnectAuthorizationScope, TOpenIdConnectToken, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue, TOpenIdConnectIdentityResource>
        //where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue>
        //where TOpenIdConnectAuthorization: DynamicEntity, IOpenIdConnectAuthorization<TOpenIdConnectClient, TAllowedGrantType,TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType, TOpenIdConnectAuthorizationScope,
        //    TOpenIdConnectAuthorization, TOpenIdConnectToken, TOpenIdConnectTokenStatus, TOpenIdConnectTokenType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue, TOpenIdConnectIdentityResource>
        //where TOpenIdConnectTokenStatus : struct,IConvertible
        //where TOpenIdConnectTokenType : struct, IConvertible
        //where  TOpenIdConnectAuthorizationStatus : struct, IConvertible
        //where TAllowedGrantType : DynamicEntity, IAllowedGrantType<TAllowedGrantTypeValue>
        //where TOpenIdConnectAuthorizationScope : DynamicEntity, IOpenIdConnectAuthorizationScope<TOpenIdConnectIdentityResource>
        //where TOpenIdConnectClientTypes : struct, IConvertible
        //where TOpenIdConnectClientConsentTypes : struct, IConvertible
        //  where TAllowedGrantTypeValue : struct, IConvertible
        //  where TOpenIdConnectIdentityResource : DynamicEntity, IOpenIdConnectIdentityResource
        // where TOpenIdConnectAuthorizationType : struct, IConvertible
    {
        public Guid Id { get; set; }
        public Guid? ClientId { get; set; }
        public String Payload { get; set; }
        public DateTime? CreatedOn { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public String Properties { get; set; }
        public TOpenIdConnectClient Client { get; set; }
        public DateTime? RedemptionDate { get; set; }
        public Guid? ReferenceId { get; set; }

        public Guid? AuthorizationId { get; set; }

       
        public TOpenIdConnectAuthorization Authorization { get; set; }
 
        public Guid? SubjectId { get; set; }
        public TOpenIdConnectTokenStatus? Status { get; set; }
        public TOpenIdConnectTokenType? Type { get; set; }
        
        //[ForeignKey("SubjectId")]
        //[JsonProperty("subject")]
        //[JsonPropertyName("subject")]
        //[DataMember(Name = "subject")]
        //public Identity Subject { get; set; }
    }

}