using System;
using System.IO;
using System.Security.Cryptography;

namespace EncryptionAndHashingLibrary
{
    public class AesEncryptionWrapper
    {
        public static readonly int CBC_KEY_SIZE = 256;
        public static readonly int CBC_IV_SIZE = 128;
        public static readonly int GCM_KEY_SIZE = 128;
        public static readonly int GCM_NONCE_SIZE = 96;

        public static byte[] CreateRandomBytes(int sizeInBits)
        {
            byte[] result = new byte[sizeInBits / 8];
            RandomNumberGenerator.Create().GetBytes(result);
            return result;
        }

        // CBC mode
        public static byte[] EncryptWithCBC(byte[] data, byte[] key)
        {
            byte[] iv = CreateRandomBytes(CBC_IV_SIZE);
            byte[] cipherText;

            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Key = key;
                aes.IV = iv;
                aes.Padding = PaddingMode.PKCS7;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (var ms = new MemoryStream())
                    using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock();

                        cipherText = ms.ToArray();
                    }
                }
            }

            byte[] completeCipherText = new byte[iv.Length + cipherText.Length];
            Array.Copy(iv, completeCipherText, iv.Length);
            Array.Copy(cipherText, 0, completeCipherText, iv.Length, cipherText.Length);

            return completeCipherText;
        }

        // GCM mode (preferred)
        public static byte[] EncryptWithGCM(byte[] data, byte[] key)
        {
            byte[] tag = new byte[GCM_KEY_SIZE / 8];
            byte[] nonce = CreateRandomBytes(GCM_NONCE_SIZE);
            byte[] cipherText = new byte[data.Length];

            byte[] completeCipherText = new byte[tag.Length + nonce.Length + cipherText.Length];

            using (var cipher = new AesGcm(key))
            {
                cipher.Encrypt(nonce, data, cipherText, tag);

                Array.Copy(tag, completeCipherText, tag.Length);
                Array.Copy(nonce, 0, completeCipherText, tag.Length, nonce.Length);
                Array.Copy(cipherText, 0, completeCipherText, tag.Length+nonce.Length, cipherText.Length);
                return completeCipherText;
            }
        }

        public static byte[] DecryptForCBC(byte[] completeCipherText, byte[] key)
        {
            byte[] iv = new byte[CBC_IV_SIZE / 8];
            byte[] cipherText = new byte[completeCipherText.Length - iv.Length];
            byte[] data;

            Array.Copy(completeCipherText, iv, iv.Length);
            Array.Copy(completeCipherText, iv.Length, cipherText, 0, cipherText.Length);

            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Key = key;
                aes.IV = iv;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (var ms = new MemoryStream())
                    using (var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(cipherText, 0, cipherText.Length);
                        cryptoStream.FlushFinalBlock();

                        data = ms.ToArray();
                    }
                }
            }

            return data;
        }

        public static byte[] DecryptForGCM(byte[] completeCipherText, byte[] key)
        {
            byte[] tag = new byte[GCM_KEY_SIZE / 8];
            byte[] nonce = new byte[GCM_NONCE_SIZE / 8];
            byte[] cipherText = new byte[completeCipherText.Length - tag.Length - nonce.Length];
            byte[] data = new byte[cipherText.Length];

            Array.Copy(completeCipherText, tag, tag.Length);
            Array.Copy(completeCipherText, tag.Length, nonce, 0, nonce.Length);
            Array.Copy(completeCipherText, tag.Length + nonce.Length, cipherText, 0, cipherText.Length);

            using (var cipher = new AesGcm(key))
            {
                cipher.Decrypt(nonce, cipherText, tag, data);

                return data;
            }
        }
    }
}