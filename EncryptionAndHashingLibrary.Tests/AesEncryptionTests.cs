using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace EncryptionAndHashingLibrary.Tests
{
    public class AesEncryptionTests
    {
        [Fact]
        public void CbcEncryptionAndDecryptionTest()
        {
            List<string> cipherTexts = new List<string>();

            string testText = "This is a short text used for encryption!";
            byte[] key = AesEncryptionWrapper.CreateRandomBytes(AesEncryptionWrapper.CBC_KEY_SIZE);

            for (int e = 0; e < 10; e++)
            {
                byte[] cipherText = AesEncryptionWrapper.Encrypt(Encoding.UTF8.GetBytes(testText), key, out byte[] iv);
                byte[] decryptedData = AesEncryptionWrapper.Decrypt(cipherText, key, iv);

                Assert.Equal(testText, Encoding.UTF8.GetString(decryptedData));

                string cipherTextPieceAsBase64 = Convert.ToBase64String(cipherText);
                Assert.DoesNotContain(cipherTextPieceAsBase64, cipherTexts);
                cipherTexts.Add(cipherTextPieceAsBase64);
            }
        }

        [Fact]
        public void GcmEncryptionAndDecryptionTest()
        {
            List<string> cipherTexts = new List<string>();

            string testText = "This is a short text used for encryption!";
            byte[] key = AesEncryptionWrapper.CreateRandomBytes(AesEncryptionWrapper.GCM_KEY_SIZE);

            for (int e = 0; e < 10; e++)
            {
                byte[] result = AesEncryptionWrapper.Encrypt(Encoding.UTF8.GetBytes(testText), key);
                byte[] decryptedData = AesEncryptionWrapper.Decrypt(result, key);

                Assert.Equal(testText, Encoding.UTF8.GetString(decryptedData));

                string cipherTextPieceAsBase64 = Convert.ToBase64String(result);
                Assert.DoesNotContain(cipherTextPieceAsBase64, cipherTexts);
                cipherTexts.Add(cipherTextPieceAsBase64);
            }
        }
    }
}
