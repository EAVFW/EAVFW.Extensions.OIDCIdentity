using EAVFramework.Shared;
using System;

namespace EAVFW.Extensions.OIDCIdentity
{
    [EntityInterface(EntityKey = "OpenId Connect Secret")]
    public interface IOpenIdConnectSecret
    {
        public string Value { get; set; }
        public DateTime? Expiration { get; set; }

        public Guid? ClientId { get; set; }
    }

}