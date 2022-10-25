using EAVFramework;
using EAVFramework.Shared;
using System;
using System.Collections.Generic;

namespace EAVFW.Extensions.OIDCIdentity
{
    
    [EntityInterface(EntityKey = "OpenId Connect Client")]
    [ConstraintMapping(AttributeKey = "Consent Type", ConstraintName = "TOpenIdConnectClientConsentTypes")]
    [ConstraintMapping(AttributeKey = "Type", ConstraintName = "TOpenIdConnectClientTypes")]

    public interface IOpenIdConnectClient<TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
        where TOpenIdConnectClientTypes : struct,IConvertible
        where TOpenIdConnectClientConsentTypes : struct, IConvertible
    {
        public Int32? AccessTokenLifetime { get; set; }
        public Guid Id { get; set; }
        public String ClientId {get;set;}


        public String PostLogoutRedirectURIs { get; set; }
        public String ClientSecret { get; set; }

        public String RedirectUris { get; set; }
        public String Properties { get; set; }
        public Boolean? RequirePKCE { get; set; }
        public TOpenIdConnectClientTypes? Type { get; set; }

        public TOpenIdConnectClientConsentTypes? ConsentType { get; set; }
        public string Name { get; set; }
    }

}