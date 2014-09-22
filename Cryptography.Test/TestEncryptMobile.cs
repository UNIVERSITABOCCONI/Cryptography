using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Apexnet.Security.Cryptography;
using System.Web;
using System.Text;

namespace Cryptography.Test
{
    [TestClass]
    public class TestEncryptMobile
    {
        private const string AESKEY = "eW6Zms2ye02Ben0Vc11rHIOp0QtPmTGP";// "GE5Kmn4dp98Epk7Maju6MMfA3PJ7245e";

        [TestMethod]
        public void TestEncryptDecrpt()
        {
            string user = "1681444";

            var cipher = new EncryptMobile();
            string enc = cipher.Encrypt(user, AESKEY, string.Empty);
            string dec = cipher.Decrypt(enc, AESKEY, string.Empty);

            Assert.AreEqual(user, dec);
        }
    }
}
