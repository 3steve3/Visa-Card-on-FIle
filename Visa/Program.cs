using System.Security.Cryptography.X509Certificates;
using System.Net.Http.Headers;
using System.Text;
using System.Web;
using System.Security.Cryptography;
using Jose;
using Newtonsoft.Json;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

namespace Visa
{
    class Visa
    {
        readonly string user = "HTF40HDN6xxxxxxxxxxxxxxxxxxxxxxxxx";
        readonly string pass = "";
        readonly string certPath = "myProject_keyAndCertBundle.p12";
        readonly string certPassword = "123";

        //For MLE
        readonly string keyId = "ef208024-e6ba-49b0-bd31-40a686a518f3";
        readonly string mleClientPrivateKey = "key_ef208024-e6ba-49b0-bd31-40a686a518f3.pem";
        readonly string mleServerPublicCertificate = "server_cert_ef208024-e6ba-49b0-bd31-40a686a518f3.pem";
        readonly HttpClient client;
        public Visa()
        {
            HttpClientHandler handler = new();
            var certificate = new X509Certificate2(certPath, certPassword);
            certificate.GetRSAPrivateKey();
            certificate.GetRSAPublicKey();
            handler.ClientCertificates.Add(certificate);
            client = new HttpClient(handler)
            {
                BaseAddress = new Uri("https://sandbox.api.visa.com")
            };
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.ASCII.GetBytes($"{user}:{pass}")));
        }

        
        static async Task Main()
        {
            Visa visa = new();
            await visa.GetCardData();

        }
        private string getEncryptedPayload(string requestBody)
        {
            RSA clientCertificate = new X509Certificate2(mleServerPublicCertificate).GetRSAPublicKey()!;
            DateTime now = DateTime.UtcNow;
            long unixTimeMilliseconds = new DateTimeOffset(now).ToUnixTimeMilliseconds();
            IDictionary<string, object> extraHeaders = new Dictionary<string, object>{
                {"kid", keyId},{"iat",unixTimeMilliseconds}
            };
            string token = JWT.Encode(requestBody, clientCertificate, JweAlgorithm.RSA_OAEP_256, JweEncryption.A128GCM, null, extraHeaders);
            return "{\"encData\":\"" + token + "\"}";
        }
        public async Task GetCardData()
        {
            string sampleContent = """
                             {
                  "requestHeader": {
                    "requestMessageId": "6da6b8b024532a2e0eacb1af58581",
                    "messageDateTime": "2019-02-35 05:25:12.327"
                  },
                  "requestData": {
                    "pANs": [
                      4072208010000000
                    ],
                    "group": "STANDARD"
                  }
                }
                """;

            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri("/cofds-web/v1/datainfo", UriKind.Relative),
                Content = new StringContent(getEncryptedPayload(sampleContent), Encoding.UTF8, "application/json"),
            };
            request.Headers.Add("keyId", keyId);
            
            var result =  await client.SendAsync(request);
            
            Console.WriteLine(GetDecryptedPayload(await result.Content.ReadAsStringAsync()));
        }
        private string GetDecryptedPayload(String encryptedPayload)
        {
            var jsonPayload = JsonConvert.DeserializeObject<EncryptedPayload>(encryptedPayload);
            return JWT.Decode(jsonPayload.encData, ImportPrivateKey(mleClientPrivateKey));
        }
        private static RSA ImportPrivateKey(string privateKeyFile)
        {
            var pemValue = Encoding.Default.GetString(File.ReadAllBytes(privateKeyFile));
            var pr = new PemReader(new StringReader(pemValue));
            var keyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            var rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);

            var rsa = RSA.Create();
            rsa.ImportParameters(rsaParams);

            return rsa;
        }
        public class EncryptedPayload
        {
            public string encData { get; set; }
        }
    }
}