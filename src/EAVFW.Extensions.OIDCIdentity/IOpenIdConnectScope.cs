using EAVFramework;
using EAVFramework.Shared;
using System;
using System.Collections.Generic;

namespace EAVFW.Extensions.OIDCIdentity
{
    [EntityInterface(EntityKey = "OpenId Connect Identity Resource")]
    public interface IOpenIdConnectIdentityResource

    {
        public Guid Id { get; set; }
        public string Name { get; set; }
    }

    [EntityInterface(EntityKey = "OpenId Connect Scope Resource")]
    [ConstraintMapping(EntityKey = "OpenId Connect Resource", ConstraintName = nameof(TOpenIdConnectResource))]
    [ConstraintMapping(EntityKey = "OpenId Connect Identity Resource", ConstraintName = nameof(TOpenIdConnectIdentityResource))]
    public interface IOpenIdConnectScopeResource <TOpenIdConnectResource, TOpenIdConnectIdentityResource>
        where TOpenIdConnectResource : DynamicEntity
         where TOpenIdConnectIdentityResource : DynamicEntity

    {

        public TOpenIdConnectResource Resource { get; set; }
        public TOpenIdConnectIdentityResource Scope { get; set; }
    }


    [EntityInterface(EntityKey = "OpenId Connect Resource")]
    public interface IOpenIdConnectResource<TOpenIdConnectScopeResource> where TOpenIdConnectScopeResource : DynamicEntity
    {
       
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string DisplayName { get; set; }
        public string Description { get; set; }

        public Boolean? ShowInDiscoveryDocument { get; set; }
       
        public string Properties { get; set; }

 
        public ICollection<TOpenIdConnectScopeResource> OpenIdConnectScopeResources { get; set; }
    }


    [EntityInterface(EntityKey = "OpenId Connect Scope")]
    public interface IOpenIdConnectScope<TOpenIdConnectScopeResource>
          where TOpenIdConnectScopeResource : DynamicEntity
    {
        public Boolean? Required { get; set; }
        public Boolean? Emphasize { get; set; }
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string DisplayName { get; set; }
        public string Properties { get; set; }
        public ICollection<TOpenIdConnectScopeResource> OpenIdConnectScopeResources { get; set; }
    }

}