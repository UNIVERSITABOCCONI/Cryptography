namespace Apexnet.Security.Cryptography
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Web;

    /* =========================================================================
     * Le parti più interessanti di questo codice sono presi da http://msdn.microsoft.com/en-us/library/3k2d54f8(v=vs.110).aspx?appId=Dev11IDEF1&l=EN-US&k=k(System.Security.Cryptography.RijndaelManaged)%3bk(RijndaelManaged)%3bk(TargetFrameworkMoniker-.NETFramework,Version%3dv4.5)%3bk(DevLang-csharp)&rd=true&cs-save-lang=1&cs-lang=csharp#code-snippet-2
     * 
     * - Per generare un segreto valido usa il metodo `GeneraSegreto`
     * - Per generare un vettore valido usa il metodo `GeneraVettore`
     * =========================================================================
     */

    /// <summary>
    /// AES (Algoritmo Rijndael)
    /// </summary>
    public class UrlCompatibleCipher : IAESCipher
    {
        /// <summary>
        /// Cifra una stringa in un token compatibile per la trasmissione in URL.
        /// Usa `Decifra(string, string, string) per decifrare.
        /// </summary>
        /// <param name="plainText">Messaggio da cifrare</param>
        /// <param name="key">Segreto con cui cifrare il messaggio (vedi `GeneraSegreto`)</param>
        /// <param name="iv">Vettore iniziale per aumentare la casualità; è consigliato mantenere il segreto fisso, ma cambiare il token per ogni messaggio (vedi `GeneraVettore`)</param>
        /// <returns>Token cifrato</returns>
        public string Encrypt(string plainText, string key, string iv)
        {
            byte[] keyBytes = HttpServerUtility.UrlTokenDecode(key);
            byte[] vectorBytes = HttpServerUtility.UrlTokenDecode(iv);

            // Encrypt the string to an array of bytes. 
            byte[] encrypted = EncryptStringToBytes(plainText, keyBytes, vectorBytes);

            return HttpServerUtility.UrlTokenEncode(encrypted);
        }

        /// <summary>
        /// Decifra un token nel messaggio originale.
        /// Usa `Cifra(string, string, string) per cifrare.
        /// </summary>
        /// <param name="cipherText">Token da decifrare</param>
        /// <param name="key">Segreto utilizzato per cifrare il messaggio</param>
        /// <param name="iv">Vettore iniziale utilizzato per cifrare il messaggio</param>
        /// <returns>Messaggio decifrato</returns>
        public string Decrypt(string cipherText, string key, string iv)
        {
            byte[] keyBytes = HttpServerUtility.UrlTokenDecode(key);
            byte[] vectorBytes = HttpServerUtility.UrlTokenDecode(iv);

            byte[] encrypted = HttpServerUtility.UrlTokenDecode(cipherText);

            // Decrypt the bytes to a string. 
            return DecryptStringFromBytes(encrypted, keyBytes, vectorBytes);
        }

        /// <summary>
        /// Genera un segreto compatibile per la trasmissione in URL che deve essere protetto e condiviso dalle parti che vogliono scambiare i messaggi in maniera cifrata.
        /// </summary>
        /// <returns>Segreto</returns>
        public string GeneraSegreto()
        {
            using (var myRijndael = new RijndaelManaged())
            {
                myRijndael.GenerateKey();
                return HttpServerUtility.UrlTokenEncode(myRijndael.Key);
            }
        }

        /// <summary>
        /// Genera un vettore iniziale compatibile per la trasmissione in URL che deve essere utilizzato per poter decifrare un messaggio cifrato.
        /// </summary>
        /// <returns>Segreto</returns>
        public string GeneraVettore()
        {
            using (var myRijndael = new RijndaelManaged())
            {
                myRijndael.GenerateIV();
                return HttpServerUtility.UrlTokenEncode(myRijndael.IV);
            }
        }

        #region /// Internal ///////////////////////////////////////////////////

        private static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption. 
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream. 
            return encrypted;

        }

        private static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption. 
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream 
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }

        #endregion
    }
}

