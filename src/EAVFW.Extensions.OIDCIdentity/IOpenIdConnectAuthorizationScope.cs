using EAVFramework;
using EAVFramework.Shared;
using Newtonsoft.Json;
using System;
using System.ComponentModel.DataAnnotations.Schema;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace EAVFW.Extensions.OIDCIdentity
{

    [EntityInterface(EntityKey = "OpenId Connect Authorization Scope")]
    [ConstraintMapping(EntityKey = "OpenId Connect Identity Resource", ConstraintName = nameof(TOpenIdConnectIdentityResource))]

    public interface IOpenIdConnectAuthorizationScope<TOpenIdConnectIdentityResource>
        where TOpenIdConnectIdentityResource : DynamicEntity
    {
        public TOpenIdConnectIdentityResource Scope { get; set; }
        public Guid? AuthorizationId { get; set; }
        public Guid? ScopeId { get; set; }
    }
 
   
}