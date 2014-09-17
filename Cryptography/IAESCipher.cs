using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Apexnet.Security.Cryptography
{
    public interface IAESCipher
    {
        string Encrypt(string plainText, string key, string iv);

        string Decrypt(string cipherText, string key, string iv);
    }
}
