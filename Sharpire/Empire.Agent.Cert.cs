using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace Sharpire
{
    public class Cert
    {

        // Version (translate __version__)
        private static string __version__ = "1.0.dev0";

        // Constants as BigInteger
        private static int bitLength = 256;
        private static BigInteger q = BigInteger.Pow(2, 255) - 19;
        private static BigInteger l = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");

        public static byte[] Hash(byte[] m)
        {
            using (var sha = SHA512.Create())
            {
                return sha.ComputeHash(m);
            }
        }
        public static byte[] ToBigEndianFixedFromLE(byte[] littleEndian, int length)
        {
            // Remove trailing zero if present
            if (littleEndian.Length > 0 && littleEndian.Last() == 0x00)
            {
                littleEndian = littleEndian.Take(littleEndian.Length - 1).ToArray();
            }

            // Reverse to big endian
            byte[] bigEndian = littleEndian.Reverse().ToArray();

            // Adjust to target length
            if (bigEndian.Length > length)
            {
                return bigEndian.Skip(bigEndian.Length - length).ToArray();
            }
            else if (bigEndian.Length < length)
            {
                return new byte[length - bigEndian.Length].Concat(bigEndian).ToArray();
            }

            return bigEndian;
        }

        // Helper to emulate Python's non-negative modulo
        public static BigInteger ModQ(BigInteger x)
        {
            BigInteger r = x % q;
            if (r < 0) r += q;
            return r;
        }

        public static BigInteger pow2(BigInteger x, int p)
        {
            while (p > 0)
            {
                x = ModQ(x * x);
                p -= 1;
            }
            return x;
        }

        public static BigInteger inv(BigInteger z)
        {
            // Adapted from curve25519_athlon.c in djb's Curve25519.
            BigInteger z2 = z * z % q;
            BigInteger z9 = (pow2(z2, 2)) * z % q; // 9
            BigInteger z11 = ModQ(z9 * z2);  // 11
            BigInteger z2_5_0 = ModQ((ModQ(z11 * z11)) * z9);  // 31 == 2^5 - 2^0
            BigInteger z2_10_0 = ModQ((pow2(z2_5_0, 5)) * z2_5_0);  // 2^10 - 2^0
            BigInteger z2_20_0 = ModQ((pow2(z2_10_0, 10)) * z2_10_0);  // ...
            BigInteger z2_40_0 = ModQ((pow2(z2_20_0, 20)) * z2_20_0);
            BigInteger z2_50_0 = ModQ((pow2(z2_40_0, 10)) * z2_10_0);
            BigInteger z2_100_0 = ModQ((pow2(z2_50_0, 50)) * z2_50_0);
            BigInteger z2_200_0 = ModQ((pow2(z2_100_0, 100)) * z2_100_0);
            BigInteger z2_250_0 = ModQ((pow2(z2_200_0, 50)) * z2_50_0);  // 2^250 - 2^0
            return ModQ((pow2(z2_250_0, 5)) * z11);  // 2^255 - 2^5 + 11 = q - 2
        }

        // d and I
        private static BigInteger d = ModQ(-121665 * (inv(121666)));
        private static BigInteger I = BigInteger.ModPow(2, (q - 1) / 4, q);

        public static BigInteger xrecover(BigInteger y)
        {
            BigInteger xx = (y * y - 1) * (inv(d * y * y + 1));
            BigInteger x = BigInteger.ModPow(xx, (q + 3) / 8, q);

            if ((ModQ(x * x - xx)) != 0)
            {
                x = ModQ(x * I);
            }

            if ((x % 2) != 0)
            {
                x = q - x;
            }

            return x;
        }

        // Base point and identity
        private static BigInteger By = ModQ(4 * (inv(5)));
        private static BigInteger Bx = xrecover(By);
        private static BigInteger[] basePoint = new BigInteger[] {
        ModQ(Bx),
        ModQ(By),
        1,
        ModQ(Bx * By)
    };
        private static BigInteger[] ident = new BigInteger[] { 0, 1, 1, 0 };

        public static BigInteger[] edwards_add(BigInteger[] P, BigInteger[] Q)
        {
            // Formula sequence 'addition-add-2008-hwcd-3'
            System.Diagnostics.Debug.WriteLine("Point 1 Value");
            System.Diagnostics.Debug.WriteLine(string.Join(", ", P));
            System.Diagnostics.Debug.WriteLine("Point 2 Value");
            System.Diagnostics.Debug.WriteLine(string.Join(", ", Q));

            BigInteger x1 = P[0], y1 = P[1], z1 = P[2], t1 = P[3];
            BigInteger x2 = Q[0], y2 = Q[1], z2 = Q[2], t2 = Q[3];

            BigInteger a = ModQ((y1 - x1) * (y2 - x2));
            BigInteger b = ModQ((y1 + x1) * (y2 + x2));
            BigInteger c = ModQ(t1 * 2 * d * t2);
            BigInteger dd = ModQ(z1 * 2 * z2);
            BigInteger e = ModQ(b - a);
            BigInteger f = ModQ(dd - c);
            BigInteger g = ModQ(dd + c);
            BigInteger h = ModQ(b + a);
            BigInteger x3 = ModQ(e * f);
            BigInteger y3 = ModQ(g * h);
            BigInteger t3 = ModQ(e * h);
            BigInteger z3 = ModQ(f * g);

            return new BigInteger[] { x3, y3, z3, t3 };
        }

        public static BigInteger[] edwards_double(BigInteger[] P)
        {
            // Formula sequence 'dbl-2008-hwcd'
            BigInteger x1 = P[0], y1 = P[1], z1 = P[2], t1 = P[3];

            BigInteger a = ModQ(x1 * x1);
            BigInteger b = ModQ(y1 * y1);
            BigInteger c = ModQ(2 * z1 * z1);
            // dd = -a
            BigInteger e = ModQ((x1 + y1) * (x1 + y1) - a - b);
            BigInteger g = ModQ(-a + b);  // dd + b
            BigInteger f = ModQ(g - c);
            BigInteger h = ModQ(-a - b);  // dd - b
            BigInteger x3 = ModQ(e * f);
            BigInteger y3 = ModQ(g * h);
            BigInteger t3 = ModQ(e * h);
            BigInteger z3 = ModQ(f * g);

            return new BigInteger[] { x3, y3, z3, t3 };
        }

        public static BigInteger[] scalarmult(BigInteger[] P, BigInteger e)
        {
            if (e == 0) return ident;
            BigInteger half = BigInteger.Divide(e, 2);
            BigInteger[] Q = scalarmult(P, half);
            Q = edwards_double(Q);
            if ((e & 1) != 0)
            {
                Q = edwards_add(Q, P);
            }
            return Q;
        }

        // basePointPow[i] == scalarmult(basePoint, 2**i)
        private static List<BigInteger[]> basePointPow = new List<BigInteger[]>();

        public static void make_basePointPow()
        {
            BigInteger[] P = basePoint;
            for (int i = 0; i < 253; i++)
            {
                basePointPow.Add(P);
                P = edwards_double(P);
            }
        }

        static Cert()
        {
            make_basePointPow();
        }

        public static BigInteger[] scalarmult_B(BigInteger e)
        {
            // scalarmult(basePoint, l) is the identity
            e = e % l;
            BigInteger[] P = ident;
            for (int i = 0; i < 253; i++)
            {
                if ((e & 1) != 0)
                {
                    P = edwards_add(P, basePointPow[i]);
                }
                e = BigInteger.Divide(e, 2);
            }
            if (e != 0) throw new Exception(e.ToString());  // assert e == 0, e
            return P;
        }

        public static byte[] encodeint(BigInteger y)
        {
            int[] bits = new int[bitLength];
            for (int i = 0; i < bitLength; i++)
            {
                bits[i] = (int)((y >> i) & 1);
            }
            byte[] output = new byte[bitLength / 8];
            for (int i = 0; i < (bitLength / 8); i++)
            {
                int sum = 0;
                for (int j = 0; j < 8; j++)
                {
                    sum += (bits[i * 8 + j] << j);
                }
                output[i] = (byte)sum;
            }
            return output;
        }

        public static byte[] encodepoint(BigInteger[] P)
        {
            BigInteger x = P[0], y = P[1], z = P[2], t = P[3];
            BigInteger zi = inv(z);
            x = ModQ(x * zi);
            y = ModQ(y * zi);
            int[] bits = new int[bitLength];
            for (int i = 0; i < (bitLength - 1); i++)
            {
                bits[i] = (int)((y >> i) & 1);
            }
            bits[bitLength - 1] = (int)(x & 1);
            byte[] output = new byte[bitLength / 8];
            for (int i = 0; i < (bitLength / 8); i++)
            {
                int sum = 0;
                for (int j = 0; j < 8; j++)
                {
                    sum += (bits[i * 8 + j] << j);
                }
                output[i] = (byte)sum;
            }
            return output;
        }

        public static int bit(byte[] h, int i)
        {
            int b = (int)h[(int)Math.Floor((double)i / 8)];
            b = b & 0xFF;
            return (b >> (i % 8)) & 1;
        }

        public static byte[] publickey_unsafe(byte[] sk)
        {
            byte[] h = Hash(sk);
            BigInteger a = BigInteger.Pow(2, (bitLength - 2));
            for (int i = 3; i < (bitLength - 2); i++)
            {
                a += BigInteger.Pow(2, i) * (bit(h, i));
            }
            BigInteger[] A = scalarmult_B(a);
            return encodepoint(A);
        }

        public static BigInteger Hint(byte[] m)
        {
            byte[] h = Hash(m);
            BigInteger s = 0;
            for (int i = 0; i < (2 * bitLength); i++)
            {
                s += BigInteger.Pow(2, i) * (bit(h, i));
            }
            return s;
        }

        public static byte[] signature_unsafe(byte[] m, byte[] sk, byte[] pk)
        {
            byte[] h = Hash(sk);
            BigInteger a = BigInteger.Pow(2, (bitLength - 2));
            for (int i = 3; i < (bitLength - 2); i++)
            {
                a += BigInteger.Pow(2, i) * (bit(h, i));
            }
            // r = Hint(bytes([h[j] for j in range(bitLength // 8, bitLength // 4)]) + m)
            int sliceLen = (int)(bitLength / 4 - bitLength / 8);
            byte[] rBytes = new byte[sliceLen];
            Array.Copy(h, (int)(bitLength / 8), rBytes, 0, sliceLen);

            using (var rm = new MemoryStream())
            using (var bw = new BinaryWriter(rm))
            {
                bw.Write(rBytes);
                bw.Write(m);
                bw.Flush();
                BigInteger r = Hint(rm.ToArray());

                BigInteger[] R2 = scalarmult_B(r);
                BigInteger S = (r + (Hint(ConcatArrays(ConcatArrays(encodepoint(R2), pk), m))) * a) % l;
                return ConcatArrays(encodepoint(R2), encodeint(S));
            }
        }

        private static byte[] ConcatArrays(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            Array.Copy(a, 0, result, 0, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);
            return result;
        }

        public static bool isoncurve(BigInteger[] P)
        {
            BigInteger x = P[0], y = P[1], z = P[2], t = P[3];
            return (ModQ(z) != 0) &&
                   (ModQ(x * y) == ModQ(z * t)) &&
                   (ModQ(y * y - x * x - z * z - d * t * t) == 0);
        }

        public static BigInteger decodeint(byte[] s)
        {
            BigInteger r = 0;
            for (int i = 0; i < bitLength; i++)
            {
                r += BigInteger.Pow(2, i) * (bit(s, i));
            }
            return r;
        }

        public static BigInteger[] decodepoint(byte[] s)
        {
            BigInteger y = 0;
            for (int i = 0; i < (bitLength - 1); i++)
            {
                y += BigInteger.Pow(2, i) * (bit(s, i));
            }
            BigInteger x = xrecover(y);
            if ((x & 1) != (bit(s, (bitLength - 1))))
            {
                x = q - x;
            }
            BigInteger[] P = new BigInteger[] { x, y, 1, ModQ(x * y) };
            if (!isoncurve(P))
            {
                throw new Exception("decoding point that is not on curve");
            }
            return P;
        }

        // Define SignatureMismatch exception class
        public class SignatureMismatch : Exception
        {
            public SignatureMismatch(string message) : base(message) { }
        }

        public static bool checkvalid(byte[] s, byte[] m, byte[] pk)
        {
            if (s.Length != (bitLength / 4))
            {
                throw new Exception("signature length is wrong");
            }

            if (pk.Length != (bitLength / 8))
            {
                throw new Exception("public-key length is wrong");
            }

            // Fix array slicing - use proper range syntax
            int rByteLength = (int)(bitLength / 8);
            int totalSigLength = (int)(bitLength / 4);

            // Extract R bytes (first half of signature)
            byte[] rBytes = new byte[rByteLength];
            Array.Copy(s, 0, rBytes, 0, rByteLength);

            // Extract S bytes (second half of signature) 
            byte[] sBytes = new byte[rByteLength];
            Array.Copy(s, rByteLength, sBytes, 0, rByteLength);

            BigInteger[] R = decodepoint(rBytes);
            BigInteger[] A = decodepoint(pk);
            BigInteger Sint = decodeint(sBytes);
            BigInteger h = Hint(ConcatArrays(ConcatArrays(encodepoint(R), pk), m));

            BigInteger[] P = scalarmult_B(Sint);
            BigInteger x1 = P[0], y1 = P[1], z1 = P[2], t1 = P[3];
            BigInteger[] temp = scalarmult(A, h);
            BigInteger[] Qval = edwards_add(R, temp);
            BigInteger x2 = Qval[0], y2 = Qval[1], z2 = Qval[2], t2 = Qval[3];

            // Fix logic - either return false OR throw exception, not both
            // Check if points are on curve and if verification equation holds
            if ((!isoncurve(P)) || (!isoncurve(Qval)))
            {
                throw new SignatureMismatch("Points are not on curve");
            }

            if (((ModQ(x1 * z2 - x2 * z1)) != 0) ||
                ((ModQ(y1 * z2 - y2 * z1)) != 0))
            {
                throw new SignatureMismatch("signature does not pass verification");
            }

            return true;
        }
    }
}
