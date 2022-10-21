using EAVFramework;
using EAVFramework.Shared;
using System;
using System.Collections.Generic;

namespace EAVFW.Extensions.OIDCIdentity
{
    [EntityInterface(EntityKey = "OpenId Connect Resource")]
   // [ConstraintMapping(EntityKey = "OpenId Connect Scope Resource", ConstraintName = nameof(TOpenIdConnectScopeResource))]
    public interface IOpenIdConnectResource 
    {
       
       // public Guid Id { get; set; }
        public string Name { get; set; }
      //  public string DisplayName { get; set; }
      //  public string Description { get; set; }

      //  public Boolean? ShowInDiscoveryDocument { get; set; }
       
     //  public string Properties { get; set; }

 
      //  public ICollection<TOpenIdConnectScopeResource> Resources { get; set; }
    }

}