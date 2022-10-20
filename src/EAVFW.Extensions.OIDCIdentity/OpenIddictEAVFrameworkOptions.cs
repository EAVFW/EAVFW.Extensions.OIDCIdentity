using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Security.Claims;

#nullable enable

namespace EAVFW.Extensions.OIDCIdentity
{


    public static class SR
    {
        public const string ID0143 = "ID0143";
        public const string ID2036 = "ID2036";
        public const string ID0240 = nameof(ID0240);
        public const string ID0239 = nameof(ID0239);
        public const string ID0241 = nameof(ID0241);
        public const string ID0198 = nameof(ID0198);
        public const string ID0124 = nameof(ID0124);
        public const string ID0199 = nameof(ID0199);
        public const string ID0200 = nameof(ID0200);
        public const string ID0195 = nameof(ID0195);
        public const string ID0242 = nameof(ID0242);
        public const string ID0243 = nameof(ID0243);
        public const string ID0244 = nameof(ID0244);
        public const string ID0247 = nameof(ID0247);
        public const string ID0248 = nameof(ID0248);
        public const string ID0249 = nameof(ID0249);
        public const string ID0245 = nameof(ID0245);
        public const string ID0203 = nameof(ID0203);
        public const string ID0062 = nameof(ID0062);
        public const string ID0246 = nameof(ID0246);
        public const string ID0202 = nameof(ID0202);
        static Dictionary<string, string> _values = new Dictionary<string, string>
        {
            [ID0143] = "The address cannot be null or empty.",
            [ID2036] = "The client identifier cannot be null or empty",
            [nameof(ID0240)] = @"An error occurred while trying to create a new application instance.
Make sure that the application entity is not abstract and has a public parameterless constructor or create a custom application store that overrides 'InstantiateAsync()' to use a custom factory.</value>",
            [nameof(ID0239)] = @"The application was concurrently updated and cannot be persisted in its current state.
Reload the application from the database and retry the operation.",
            [nameof(ID0241)] = @"The authorization was concurrently updated and cannot be persisted in its current state.
Reload the authorization from the database and retry the operation.",

        [ nameof(ID0198)] ="",
        [nameof(ID0124)] = "",
            [nameof(ID0199)] = "",
            [nameof(ID0200)] = "",
            [nameof(ID0195)] = "",
            [nameof(ID0242)] = "",
            [nameof(ID0243)] = "",
            [nameof(ID0244)] = "",
            [nameof(ID0247)] = "",
            [nameof(ID0248)] = "",
            [nameof(ID0249)] = "",
            [nameof(ID0245)] = "",
            [nameof(ID0203)] = "",
            [nameof(ID0062)] = "",
            [nameof(ID0246)] = "",
        };

     

        public static string GetResourceString(string id)
        {
            return _values[id];
        }
 
    }
    /// <summary>
    /// Provides various settings needed to configure
    /// the OpenIddict Entity Framework Core integration.
    /// </summary>
    public class OpenIddictEAVFrameworkOptions
    {
        /// <summary>
        /// Gets or sets the concrete type of the <see cref="DbContext"/> used by the
        /// OpenIddict Entity Framework Core stores. If this property is not populated,
        /// an exception is thrown at runtime when trying to use the stores.
        /// </summary>
        public Type? DbContextType { get; set; }

        public ClaimsPrincipal Principal { get; set; }
    }

     
}