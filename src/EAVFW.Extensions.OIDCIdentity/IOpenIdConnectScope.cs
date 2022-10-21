using EAVFramework;
using EAVFramework.Shared;
using System;
using System.Collections.Generic;

namespace EAVFW.Extensions.OIDCIdentity
{


    [EntityInterface(EntityKey = "OpenId Connect Scope")]
    [ConstraintMapping(EntityKey = "OpenId Connect Scope Resource", ConstraintName = nameof(TOpenIdConnectScopeResource))]
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