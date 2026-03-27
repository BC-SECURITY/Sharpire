using System;
using System.Security.Cryptography;

namespace AesGcmEncryption
{
    public static class AesGcm
    {
        // Encrypts plaintext with AES-256-GCM and produces ciphertext + 16-byte authentication tag
        public static void Encrypt(byte[] key, byte[] nonce, byte[] plaintext, out byte[] ciphertext, out byte[] tag)
        {
            // H = AES(key, 0^128)
            byte[] H = AesEncryptBlock(key, new byte[16]);

            // J0 = nonce || 0x00000001 (for 96-bit nonce)
            byte[] J0 = new byte[16];
            Array.Copy(nonce, 0, J0, 0, 12);
            J0[15] = 0x01;

            // Encrypt: ciphertext = GCTR(key, inc32(J0), plaintext)
            byte[] ICB = (byte[])J0.Clone();
            IncrementCounter(ICB);
            ciphertext = GCTR(key, ICB, plaintext);

            // Tag: T = MSBt(GHASH(H, AAD, C) XOR AES(key, J0))
            byte[] ghash = GHASH(H, null, ciphertext);
            byte[] encJ0 = AesEncryptBlock(key, J0);
            tag = new byte[16];
            for (int i = 0; i < 16; i++)
                tag[i] = (byte)(ghash[i] ^ encJ0[i]);
        }

        // Decrypts ciphertext with AES-256-GCM, verifies tag, and produces plaintext
        public static bool Decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, out byte[] plaintext)
        {
            // H = AES(key, 0^128)
            byte[] H = AesEncryptBlock(key, new byte[16]);

            // J0 = nonce || 0x00000001
            byte[] J0 = new byte[16];
            Array.Copy(nonce, 0, J0, 0, 12);
            J0[15] = 0x01;

            // Compute expected tag
            byte[] ghash = GHASH(H, null, ciphertext);
            byte[] encJ0 = AesEncryptBlock(key, J0);
            byte[] expectedTag = new byte[16];
            for (int i = 0; i < 16; i++)
                expectedTag[i] = (byte)(ghash[i] ^ encJ0[i]);

            if (!ConstantTimeEquals(expectedTag, tag))
            {
                plaintext = null;
                return false;
            }

            // Decrypt: plaintext = GCTR(key, inc32(J0), ciphertext)
            byte[] ICB = (byte[])J0.Clone();
            IncrementCounter(ICB);
            plaintext = GCTR(key, ICB, ciphertext);
            return true;
        }

        // Single AES-256-ECB block encrypt (16 bytes in, 16 bytes out)
        private static byte[] AesEncryptBlock(byte[] key, byte[] block)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = key;
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(block, 0, 16);
                }
            }
        }

        // Increment the rightmost 32 bits of a 16-byte counter block (big-endian)
        private static void IncrementCounter(byte[] counter)
        {
            for (int i = 15; i >= 12; i--)
            {
                if (++counter[i] != 0)
                    break;
            }
        }

        // GCTR: AES-CTR mode encryption/decryption
        private static byte[] GCTR(byte[] key, byte[] icb, byte[] input)
        {
            if (input == null || input.Length == 0)
                return new byte[0];

            byte[] output = new byte[input.Length];
            byte[] counter = (byte[])icb.Clone();

            int fullBlocks = input.Length / 16;
            int remainder = input.Length % 16;

            for (int i = 0; i < fullBlocks; i++)
            {
                byte[] encryptedCounter = AesEncryptBlock(key, counter);
                for (int j = 0; j < 16; j++)
                    output[i * 16 + j] = (byte)(input[i * 16 + j] ^ encryptedCounter[j]);
                IncrementCounter(counter);
            }

            if (remainder > 0)
            {
                byte[] encryptedCounter = AesEncryptBlock(key, counter);
                int offset = fullBlocks * 16;
                for (int j = 0; j < remainder; j++)
                    output[offset + j] = (byte)(input[offset + j] ^ encryptedCounter[j]);
            }

            return output;
        }

        // GHASH: universal hash function over GF(2^128)
        private static byte[] GHASH(byte[] H, byte[] aad, byte[] ciphertext)
        {
            byte[] Y = new byte[16]; // accumulator, starts at 0

            // Process AAD blocks
            if (aad != null && aad.Length > 0)
            {
                int aadBlocks = (aad.Length + 15) / 16;
                for (int i = 0; i < aadBlocks; i++)
                {
                    byte[] block = new byte[16];
                    int offset = i * 16;
                    int len = Math.Min(16, aad.Length - offset);
                    Array.Copy(aad, offset, block, 0, len);
                    // zero-pad is implicit since block is initialized to 0

                    for (int j = 0; j < 16; j++)
                        Y[j] ^= block[j];
                    Y = GfMul(Y, H);
                }
            }

            // Process ciphertext blocks
            if (ciphertext != null && ciphertext.Length > 0)
            {
                int ctBlocks = (ciphertext.Length + 15) / 16;
                for (int i = 0; i < ctBlocks; i++)
                {
                    byte[] block = new byte[16];
                    int offset = i * 16;
                    int len = Math.Min(16, ciphertext.Length - offset);
                    Array.Copy(ciphertext, offset, block, 0, len);

                    for (int j = 0; j < 16; j++)
                        Y[j] ^= block[j];
                    Y = GfMul(Y, H);
                }
            }

            // Length block: 64-bit AAD bit length || 64-bit ciphertext bit length (big-endian)
            byte[] lengthBlock = new byte[16];
            ulong aadBitLen = (ulong)((aad != null ? aad.Length : 0) * 8);
            ulong ctBitLen = (ulong)((ciphertext != null ? ciphertext.Length : 0) * 8);
            WriteBigEndianUInt64(lengthBlock, 0, aadBitLen);
            WriteBigEndianUInt64(lengthBlock, 8, ctBitLen);

            for (int j = 0; j < 16; j++)
                Y[j] ^= lengthBlock[j];
            Y = GfMul(Y, H);

            return Y;
        }

        // GF(2^128) multiplication using bit-by-bit method
        // Reducing polynomial: x^128 + x^7 + x^2 + x + 1 (R = 0xE1 << 120)
        private static byte[] GfMul(byte[] X, byte[] Y)
        {
            byte[] Z = new byte[16]; // result accumulator
            byte[] V = (byte[])Y.Clone();

            for (int i = 0; i < 128; i++)
            {
                // Check bit i of X (MSB first: bit 0 is MSB of byte 0)
                int byteIndex = i / 8;
                int bitIndex = 7 - (i % 8);
                if ((X[byteIndex] & (1 << bitIndex)) != 0)
                {
                    for (int j = 0; j < 16; j++)
                        Z[j] ^= V[j];
                }

                // Check if LSB of V is set (rightmost bit = bit 7 of byte 15)
                bool lsbSet = (V[15] & 0x01) != 0;

                // Right-shift V by 1 bit
                for (int j = 15; j > 0; j--)
                    V[j] = (byte)((V[j] >> 1) | ((V[j - 1] & 0x01) << 7));
                V[0] >>= 1;

                // If LSB was set, XOR with R (0xE1 in MSB position)
                if (lsbSet)
                    V[0] ^= 0xE1;
            }

            return Z;
        }

        private static void WriteBigEndianUInt64(byte[] buffer, int offset, ulong value)
        {
            buffer[offset + 0] = (byte)(value >> 56);
            buffer[offset + 1] = (byte)(value >> 48);
            buffer[offset + 2] = (byte)(value >> 40);
            buffer[offset + 3] = (byte)(value >> 32);
            buffer[offset + 4] = (byte)(value >> 24);
            buffer[offset + 5] = (byte)(value >> 16);
            buffer[offset + 6] = (byte)(value >> 8);
            buffer[offset + 7] = (byte)(value);
        }

        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }
    }
}
