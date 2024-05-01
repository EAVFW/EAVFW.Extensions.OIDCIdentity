using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace EAVFW.Extensions.OIDCIdentity.Services
{
    public static class KeyvaultCertificateProvider
    {

        


        public static IEnumerable<X509Certificate2> LoadCertificateVerisons(string managedIdentityUserid,
    string keyVaultName,
    string certificateName, TokenCredential token=null)
        {
            token ??= new ManagedIdentityCredential(managedIdentityUserid);

            var keyVaultUrl = new Uri($"https://{keyVaultName}.vault.azure.net");
            var certificateClient = new CertificateClient(keyVaultUrl,token);
            var secretClient = new SecretClient(keyVaultUrl, token);

            var versions = certificateClient.GetPropertiesOfCertificateVersions(certificateName).ToArray();

            foreach (var certificate in versions)
            {
                if (!certificate.Enabled.GetValueOrDefault(false) ||
                    certificate.ExpiresOn <= DateTimeOffset.UtcNow) continue;

                var certificateSecret = secretClient.GetSecret(certificate.Name, certificate.Version).Value;
                var privateKey = Convert.FromBase64String(certificateSecret.Value);
                yield return new X509Certificate2(privateKey);
            }
        }

        internal static IEnumerable<X509Certificate2> LoadCertificateVerisons(string managedIdentityUserId, string vaultName, object signingCertificateName)
        {
            throw new NotImplementedException();
        }
    }


}
