using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace EncryptionAndHashingLibrary
{
    public class HashWrapper
    {
        public static byte[] CreateHash(byte[] data)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                return sha256Hash.ComputeHash(data);
            }
        }
    }
}
