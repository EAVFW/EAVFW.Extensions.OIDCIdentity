using EAVFramework.Shared;
using System;

namespace EAVFW.Extensions.OIDCIdentity
{

   

    [EntityInterface(EntityKey = "Allowed Grant Type")]
    [ConstraintMapping(AttributeKey = "Allowed Grant Type Value", ConstraintName = nameof(TAllowedGrantTypeValue))]
    public interface IAllowedGrantType<TAllowedGrantTypeValue>
        where TAllowedGrantTypeValue : struct, IConvertible
    {
        public TAllowedGrantTypeValue? AllowedGrantTypeValue { get; set; }
    }

}