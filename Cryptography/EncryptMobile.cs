using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Apexnet.Security.Cryptography
{
    /// <summary>
    /// Algoritmo la cui compatibilità è stata testata sulle app mobile di iOS, Android, Win Store, Win Phone
    /// </summary>
    public class EncryptMobile : IAESCipher
    {

        public string Encrypt(string plainText, string key, string iv)
        {
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            //aes.BlockSize = 128; //aes.KeySize=256;
            aes.IV = new byte[16];  //Encoding.UTF8.GetBytes(AesIV128);
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            // Convert string to byte array
            byte[] src = Encoding.UTF8.GetBytes(plainText);

            // encryption
            using (ICryptoTransform encrypt = aes.CreateEncryptor())
            {
                byte[] dest = encrypt.TransformFinalBlock(src, 0, src.Length);

                // Convert byte array to Base64 strings
                return Convert.ToBase64String(dest);
                //return HttpUtility.UrlEncode(Convert.ToBase64String(dest));
            }
        }

        public string Decrypt(string cipherText, string key, string iv)
        {
             try
            {
                AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
                //aes.BlockSize = 128; //aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.IV = new byte[16];// Encoding.UTF8.GetBytes("DBDF15AA65379176");
                aes.Key = Encoding.UTF8.GetBytes(key);

                // Convert Base64 strings to byte array
                byte[] src = System.Convert.FromBase64String(cipherText);

                // decryption
                using (ICryptoTransform decrypt = aes.CreateDecryptor())
                {
                    byte[] dest = decrypt.TransformFinalBlock(src, 0, src.Length);
                    return Encoding.UTF8.GetString(dest);
                }
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}