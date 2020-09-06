using System;
using System.Text;

namespace EncryptionAndHashingLibrary
{
    public class Tools
    {
        public static byte[] GetPasswordAsEncryptionKey(int keySizeInBits, string password)
        {
            byte[] passwordAsBytes = Encoding.UTF8.GetBytes(password);

            byte[] key = new byte[AesEncryptionWrapper.CreateRandomBytes(keySizeInBits).Length];

            // Copy password over key ..
            Array.Copy(passwordAsBytes, 0, key, 0,
                (key.Length > passwordAsBytes.Length) ? passwordAsBytes.Length : key.Length);
            // .. and start over if longer
            if (passwordAsBytes.Length > key.Length)
            {
                int pIndex = key.Length;
                while (pIndex < passwordAsBytes.Length)
                {
                    for (int kIndex = 0; kIndex < key.Length && pIndex < passwordAsBytes.Length; kIndex++, pIndex++)
                    {
                        key[kIndex] += passwordAsBytes[pIndex];
                    }
                }
            }

            return key;
        }
    }
}
