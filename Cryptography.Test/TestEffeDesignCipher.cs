using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Apexnet.Security.Cryptography;

namespace Cryptography.Test
{
    [TestClass]
    public class TestEffeDesignCipher
    {
        private const string Messaggio = "Elvis in realtà non è morto.";
        private const string Segreto = "v7'b3R]2cT4z3/wa";
        private const string Vettore = "vT6QgKRLCaFX1rV7IM1flVdsj6GNmycZ";

        [TestMethod]
        public void ShouldCifrareDecifrare()
        {
            var cipher = new EffeDesignCipher();

            var token = cipher.Encrypt(Messaggio, Segreto, Vettore);
            var risultato = cipher.Decrypt(token, Segreto, Vettore);

            Assert.AreEqual(risultato, Messaggio);
            Assert.AreEqual(token, "nK1j96MlBgh3NnGYQ/1gEqmR9m3D+S6xXUo3Rsqp558=");
        }
    }
}
