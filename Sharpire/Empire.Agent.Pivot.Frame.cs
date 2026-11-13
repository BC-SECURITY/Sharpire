using System;
using System.Collections.Generic;

namespace Sharpire
{
    // v2 pivot frame codec. Wire layout (big-endian, raw bytes, no base64):
    //   kind(1) | count(2) | hop_len(2) | body_len(4) | hop(hop_len) | body(body_len)
    internal static class V2Frame
    {
        public const int MAX_BODY = 16 * 1024 * 1024;
        public const int MAX_COUNT = 1024;
        public const int HEADER_LEN = 9;

        public const byte KIND_REPLY = 0;
        public const byte KIND_RELAY = 1;

        internal sealed class Decoded
        {
            public byte kind;
            public int count;
            public byte[] hop;
            public byte[] body;
        }

        internal sealed class Batch
        {
            public byte[] reply;
            public List<byte[]> relayFrames;
        }

        public static byte[] Encode(byte kind, int count, byte[] hop, byte[] body)
        {
            if (hop == null) hop = new byte[0];
            if (body == null) body = new byte[0];
            if (count < 0 || count > MAX_COUNT)
                throw new ArgumentException("frame count out of range: " + count);
            if (hop.Length > 0xFFFF)
                throw new ArgumentException("frame hop too long: " + hop.Length);
            if (body.Length > MAX_BODY)
                throw new ArgumentException("frame body too large: " + body.Length);

            byte[] frame = new byte[HEADER_LEN + hop.Length + body.Length];
            frame[0] = kind;
            frame[1] = (byte)((count >> 8) & 0xFF);
            frame[2] = (byte)(count & 0xFF);
            frame[3] = (byte)((hop.Length >> 8) & 0xFF);
            frame[4] = (byte)(hop.Length & 0xFF);
            int bl = body.Length;
            frame[5] = (byte)((bl >> 24) & 0xFF);
            frame[6] = (byte)((bl >> 16) & 0xFF);
            frame[7] = (byte)((bl >> 8) & 0xFF);
            frame[8] = (byte)(bl & 0xFF);
            Buffer.BlockCopy(hop, 0, frame, HEADER_LEN, hop.Length);
            Buffer.BlockCopy(body, 0, frame, HEADER_LEN + hop.Length, body.Length);
            return frame;
        }

        public static Decoded ReadFrame(Func<int, byte[]> recvExact)
        {
            byte[] h = recvExact(HEADER_LEN);
            if (h == null || h.Length != HEADER_LEN)
                throw new InvalidOperationException("short frame header");

            byte kind = h[0];
            int count = (h[1] << 8) | h[2];
            int hopLen = (h[3] << 8) | h[4];
            uint bodyLen = ((uint)h[5] << 24) | ((uint)h[6] << 16) | ((uint)h[7] << 8) | h[8];

            if (bodyLen > (uint)MAX_BODY)
                throw new InvalidOperationException("frame body too large: " + bodyLen);
            if (count > MAX_COUNT)
                throw new InvalidOperationException("frame count too large: " + count);

            byte[] hop = hopLen == 0 ? new byte[0] : recvExact(hopLen);
            byte[] body = bodyLen == 0 ? new byte[0] : recvExact((int)bodyLen);
            if (hop.Length != hopLen || body.Length != (int)bodyLen)
                throw new InvalidOperationException("short frame payload");

            return new Decoded { kind = kind, count = count, hop = hop, body = body };
        }

        public static byte[] BuildBatch(byte[] reply, IList<byte[]> relayFrames)
        {
            if (relayFrames == null) relayFrames = new List<byte[]>();
            List<byte[]> parts = new List<byte[]>();
            parts.Add(Encode(KIND_REPLY, relayFrames.Count, null, reply));
            int total = parts[0].Length;
            foreach (byte[] rf in relayFrames)
            {
                byte[] enc = Encode(KIND_RELAY, 0, null, rf);
                parts.Add(enc);
                total += enc.Length;
            }
            byte[] outBuf = new byte[total];
            int off = 0;
            foreach (byte[] p in parts)
            {
                Buffer.BlockCopy(p, 0, outBuf, off, p.Length);
                off += p.Length;
            }
            return outBuf;
        }

        public static Batch ReadBatch(Func<int, byte[]> recvExact)
        {
            Decoded first = ReadFrame(recvExact);
            if (first.kind != KIND_REPLY)
                throw new InvalidOperationException("batch must start with a reply frame, got kind " + first.kind);

            List<byte[]> relays = new List<byte[]>();
            for (int i = 0; i < first.count; i++)
            {
                Decoded f = ReadFrame(recvExact);
                if (f.kind != KIND_RELAY)
                    throw new InvalidOperationException("expected relay frame, got kind " + f.kind);
                relays.Add(f.body);
            }
            return new Batch { reply = first.body, relayFrames = relays };
        }
    }
}
