using EAVFramework.Shared;
using System;

namespace EAVFW.Extensions.OIDCIdentity
{
    [EntityInterface(EntityKey = "OpenId Connect Identity Resource")]
    public interface IOpenIdConnectIdentityResource

    {
        public Guid Id { get; set; }
        public string Name { get; set; }
    }

}