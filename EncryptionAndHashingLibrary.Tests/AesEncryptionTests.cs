using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace EncryptionAndHashingLibrary.Tests
{
    public class AesEncryptionTests
    {
        [Fact]
        public void EncryptionAndDecryptionTestCBC()
        {
            List<string> cipherTexts = new List<string>();

            string testText = "This is a short text used for encryption!";
            byte[] key = AesEncryptionWrapper.CreateRandomBytes(AesEncryptionWrapper.CBC_KEY_SIZE);

            for (int e = 0; e < 10; e++)
            {
                byte[] cipherText = AesEncryptionWrapper.EncryptWithCBC(Encoding.UTF8.GetBytes(testText), key);
                byte[] decryptedData = AesEncryptionWrapper.DecryptForCBC(cipherText, key);

                Assert.Equal(testText, Encoding.UTF8.GetString(decryptedData));

                string cipherTextPieceAsBase64 = Convert.ToBase64String(cipherText);
                Assert.DoesNotContain(cipherTextPieceAsBase64, cipherTexts);
                cipherTexts.Add(cipherTextPieceAsBase64);
            }
        }

        [Fact]
        public void EncryptionAndDecryptionTestGCM()
        {
            List<string> cipherTexts = new List<string>();

            string testText = "This is a short text used for encryption!";
            byte[] key = AesEncryptionWrapper.CreateRandomBytes(AesEncryptionWrapper.GCM_KEY_SIZE);

            for (int e = 0; e < 10; e++)
            {
                byte[] result = AesEncryptionWrapper.EncryptWithGCM(Encoding.UTF8.GetBytes(testText), key);
                byte[] decryptedData = AesEncryptionWrapper.DecryptForGCM(result, key);

                Assert.Equal(testText, Encoding.UTF8.GetString(decryptedData));

                string cipherTextPieceAsBase64 = Convert.ToBase64String(result);
                Assert.DoesNotContain(cipherTextPieceAsBase64, cipherTexts);
                cipherTexts.Add(cipherTextPieceAsBase64);
            }
        }
    }
}
