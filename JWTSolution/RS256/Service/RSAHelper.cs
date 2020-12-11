using Newtonsoft.Json;
using System.IO;
using System.Security.Cryptography;

namespace RS256.Service
{
    public static class RSAHelper
    {
        private const int DWKEYSIZE = 2048;
        /// <summary>
        /// 读取RSAkey
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="withPrivate"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public static bool TryGetKeyParameters(string filePath, bool withPrivate, out RSAParameters parameters)
        {
            parameters = default;
            string fileName = withPrivate ? "key.json" : "key.public.json";
            string fileComplatePath = Path.Combine(filePath, fileName);
            if (!File.Exists(fileComplatePath))
                return false;

            parameters = JsonConvert.DeserializeObject<RSAParameters>(File.ReadAllText(fileComplatePath));
            return true;
        }

        /// <summary>
        /// 生成RSA公、私钥
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="withPrivate"></param>
        /// <returns></returns>
        public static RSAParameters GenerateAndSaveKey(string filePath, bool withPrivate = true)
        {
            RSAParameters publicKey, privateKey;
            using (var rsa = new RSACryptoServiceProvider(DWKEYSIZE))
            {
                try
                {
                    privateKey = rsa.ExportParameters(true);
                    publicKey = rsa.ExportParameters(false); 
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
                File.WriteAllText(Path.Combine(filePath, "key.json"), JsonConvert.SerializeObject(privateKey));
                File.WriteAllText(Path.Combine(filePath, "key.public.json"), JsonConvert.SerializeObject(publicKey));
                return withPrivate ? privateKey : publicKey;
            }
        }
    }
}
