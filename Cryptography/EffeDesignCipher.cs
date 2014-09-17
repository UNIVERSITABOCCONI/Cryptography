using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Apexnet.Security.Cryptography
{
    public class EffeDesignCipher : IAESCipher
    {
        public string Encrypt(string plainText, string key, string iv)
        {
            var keyBytes = Encoding.UTF8.GetBytes(key);
            var vectorBytes = Encoding.UTF8.GetBytes(iv);

            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (keyBytes == null || keyBytes.Length <= 0)
                throw new ArgumentNullException("key");

            byte[] encrypted;
            using (var rijAlg = new RijndaelManaged())
            {
                rijAlg.BlockSize = 256;
                rijAlg.Key = keyBytes;
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.IV = vectorBytes;

                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);
                using (var msEncrypt = new MemoryStream())
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                        swEncrypt.Write(plainText);
                    encrypted = msEncrypt.ToArray();
                }
            }

            return Convert.ToBase64String(encrypted);
        }

        public string Decrypt(string cipherText, string key, string iv)
        {
            var cipherTextBytes = Convert.FromBase64String(cipherText);
            var keyBytes = Encoding.UTF8.GetBytes(key);
            var vectorBytes = Encoding.UTF8.GetBytes(iv);

            if (cipherTextBytes == null || cipherTextBytes.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (keyBytes == null || keyBytes.Length <= 0)
                throw new ArgumentNullException("key");

            string plaintext;
            using (var rijAlg = new RijndaelManaged())
            {
                rijAlg.BlockSize = 256;
                rijAlg.Key = keyBytes;
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.IV = vectorBytes;

                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);
                using (var msDecrypt = new MemoryStream(cipherTextBytes))
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (var srDecrypt = new StreamReader(csDecrypt))
                    plaintext = srDecrypt.ReadToEnd();
            }
            return plaintext;
        }
    }
}
