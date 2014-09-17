using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Apexnet.Security.Cryptography
{
    public class NullCipher : IAESCipher
    {
        public string Encrypt(string plainText, string key, string iv)
        {
            return plainText;
        }

        public string Decrypt(string cipherText, string key, string iv)
        {
            return cipherText;
        }
    }
}
