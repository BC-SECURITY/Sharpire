using System;
using System.Numerics;
using System.Linq;

namespace ChaChaEncryption
{

    //class that handles ChaCha20 functionality
    public class ChaCha20
    {
        private const int ROUNDS = 20;

        private static uint Rotate(uint v, int c) => (v << c) | (v >> (32 - c));

        private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b; d ^= a; d = Rotate(d, 16);
            c += d; b ^= c; b = Rotate(b, 12);
            a += b; d ^= a; d = Rotate(d, 8);
            c += d; b ^= c; b = Rotate(b, 7);
        }

        //Chacha20 encrypt/decrypt
        public static void Encrypt(byte[] key, byte[] nonce, uint counter, byte[] input, byte[] output)
        {
            uint[] state = new uint[16];
            byte[] constants = System.Text.Encoding.ASCII.GetBytes("expand 32-byte k");
            for (int i = 0; i < 4; i++) state[i] = BitConverter.ToUInt32(constants, i * 4);
            for (int i = 0; i < 8; i++) state[4 + i] = BitConverter.ToUInt32(key, i * 4);
            state[12] = counter;
            state[13] = BitConverter.ToUInt32(nonce, 0);
            state[14] = BitConverter.ToUInt32(nonce, 4);
            state[15] = BitConverter.ToUInt32(nonce, 8);

            byte[] block = new byte[64];
            for (int i = 0; i < input.Length; i += 64)
            {
                uint[] workingState = (uint[])state.Clone();
                for (int r = 0; r < ROUNDS; r += 2)
                {
                    QuarterRound(ref workingState[0], ref workingState[4], ref workingState[8], ref workingState[12]);
                    QuarterRound(ref workingState[1], ref workingState[5], ref workingState[9], ref workingState[13]);
                    QuarterRound(ref workingState[2], ref workingState[6], ref workingState[10], ref workingState[14]);
                    QuarterRound(ref workingState[3], ref workingState[7], ref workingState[11], ref workingState[15]);
                    QuarterRound(ref workingState[0], ref workingState[5], ref workingState[10], ref workingState[15]);
                    QuarterRound(ref workingState[1], ref workingState[6], ref workingState[11], ref workingState[12]);
                    QuarterRound(ref workingState[2], ref workingState[7], ref workingState[8], ref workingState[13]);
                    QuarterRound(ref workingState[3], ref workingState[4], ref workingState[9], ref workingState[14]);
                }

                for (int j = 0; j < 16; j++)
                    workingState[j] += state[j];

                for (int j = 0; j < 16; j++)
                    Array.Copy(BitConverter.GetBytes(workingState[j]), 0, block, j * 4, 4);

                int len = Math.Min(64, input.Length - i);
                for (int j = 0; j < len; j++)
                    output[i + j] = (byte)(input[i + j] ^ block[j]);

                state[12]++;
            }
        }
    }

    //Handles Poly1305 functionality
    public class Poly1305
    {
        private const int BLOCK_SIZE = 16;

        //Compute a poly1305 tag
        public static byte[] ComputeTag(byte[] ciphertext, byte[] aad, byte[] key32)
        {
            if (key32.Length != 32)
                throw new ArgumentException("Poly1305 key must be 32 bytes");

            byte[] rBytes = new byte[16];
            Array.Copy(key32, 0, rBytes, 0, 16);
            ClampR(rBytes);

            BigInteger r = LoadLEUnsigned(rBytes);
            BigInteger s = LoadLEUnsigned(key32, 16);

            BigInteger a = BigInteger.Zero;
            BigInteger p = (BigInteger.One << 130) - 5;

            void ProcessBlock(byte[] block)
            {
                byte[] tmp = new byte[block.Length + 1];
                Array.Copy(block, tmp, block.Length);
                tmp[block.Length] = 0x01;
                BigInteger n = LoadLEUnsigned(tmp);
                a = (a + n) * r % p;
            }

            // Process AAD (empty in your case)
            if (aad != null && aad.Length > 0)
            {
                for (int i = 0; i < aad.Length; i += 16)
                    ProcessBlock(aad.Skip(i).Take(Math.Min(16, aad.Length - i)).ToArray());

                if (aad.Length % 16 != 0)
                    ProcessBlock(new byte[0]); // Pad
            }

            // Process ciphertext
            for (int i = 0; i < ciphertext.Length; i += 16)
                ProcessBlock(ciphertext.Skip(i).Take(Math.Min(16, ciphertext.Length - i)).ToArray());

            if (ciphertext.Length % 16 != 0)
                ProcessBlock(new byte[0]); // Pad

            // Add length block (AAD len, ciphertext len)
            byte[] lengthBlock = new byte[16];
            BitConverter.GetBytes((ulong)(aad?.Length ?? 0)).CopyTo(lengthBlock, 0);
            BitConverter.GetBytes((ulong)ciphertext.Length).CopyTo(lengthBlock, 8);
            ProcessBlock(lengthBlock);

            a = (a + s) % (BigInteger.One << 128);
            byte[] tag = a.ToByteArray();
            Array.Resize(ref tag, 16);
            return tag;
        }

        private static void ClampR(byte[] r)
        {
            r[3] &= 15;
            r[7] &= 15;
            r[11] &= 15;
            r[15] &= 15;

            r[4] &= 252;
            r[8] &= 252;
            r[12] &= 252;
        }

        private static BigInteger LoadLEUnsigned(byte[] data, int offset = 0)
        {
            byte[] tmp = new byte[data.Length - offset];
            Array.Copy(data, offset, tmp, 0, tmp.Length);
            byte[] extended = new byte[tmp.Length + 1];
            Array.Copy(tmp, extended, tmp.Length);
            return new BigInteger(extended);
        }
    }

    //handles chacha20poly1305 functionality TOGETHER
    public static class ChaCha20Poly1305
    {

        //Encrypts (gets chacha20 encryption and poly1305 tag)
        public static void Encrypt(byte[] key, byte[] nonce, byte[] plaintext, out byte[] ciphertext, out byte[] tag)
        {
            byte[] keystream = new byte[64];
            ChaCha20.Encrypt(key, nonce, 0, new byte[64], keystream);
            byte[] polyKey = new byte[32];
            Array.Copy(keystream, 0, polyKey, 0, 32);

            byte[] ciphertextOut = new byte[plaintext.Length];
            ChaCha20.Encrypt(key, nonce, 1, plaintext, ciphertextOut);

            tag = Poly1305.ComputeTag(ciphertextOut, null, polyKey);
            ciphertext = ciphertextOut;
        }

        //Decrypts (decrypts chacha20 data and verifies poly1305 tag)
        public static bool Decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, out byte[] plaintext)
        {
            byte[] keystream = new byte[64];
            ChaCha20.Encrypt(key, nonce, 0, new byte[64], keystream);
            byte[] polyKey = new byte[32];
            Array.Copy(keystream, 0, polyKey, 0, 32);

            byte[] computedTag = Poly1305.ComputeTag(ciphertext, null, polyKey);
            if (!ConstantTimeEquals(computedTag, tag))
            {
                plaintext = null;
                return false; // Tag mismatch
            }

            plaintext = new byte[ciphertext.Length];
            ChaCha20.Encrypt(key, nonce, 1, ciphertext, plaintext);
            return true;
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
