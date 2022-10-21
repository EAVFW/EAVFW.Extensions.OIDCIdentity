using EAVFramework;
using EAVFramework.Shared;

namespace EAVFW.Extensions.OIDCIdentity
{
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

}