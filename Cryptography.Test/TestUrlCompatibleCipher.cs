using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Apexnet.Security.Cryptography;

namespace Cryptography.Test
{
    [TestClass]
    public class TestUrlCompatibleCipher
    {

        private const string Messaggio = "Elvis in realtà non è morto.";

        [TestMethod]
        public void ShouldCifrareDecifrare()
        {
            var cipher = new UrlCompatibleCipher();

            var segreto = cipher.GeneraSegreto();
            var vettore = cipher.GeneraVettore();

            var token = cipher.Encrypt(Messaggio, segreto, vettore);
            var risultato = cipher.Decrypt(token, segreto, vettore);

            Assert.AreEqual(risultato, Messaggio);
        }
    }
}
