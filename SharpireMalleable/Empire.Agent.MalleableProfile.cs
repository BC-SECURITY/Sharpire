using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Web.Script.Serialization;

namespace Sharpire
{
    // Runtime v1 malleable profile schema shared with Gopire and the Empire server.
    // See empire/server/common/malleable/profile.py::serialize_for_agent for the
    // canonical producer; any schema bump MUST touch all three implementations.
    public class MalleableProfile
    {
        public int V;
        public int Sleep;
        public int Jitter;
        public Dictionary<string, Section> Sections;

        public static MalleableProfile Parse(string b64Json)
        {
            if (string.IsNullOrEmpty(b64Json) || string.IsNullOrWhiteSpace(b64Json))
            {
                return null;
            }

            try
            {
                string trimmed = b64Json.Trim();
                byte[] raw;
                try
                {
                    raw = Convert.FromBase64String(trimmed);
                }
                catch (FormatException)
                {
                    // Tolerate missing '=' padding — some template pipelines strip it.
                    int pad = trimmed.Length % 4;
                    if (pad != 0)
                    {
                        trimmed = trimmed + new string('=', 4 - pad);
                        raw = Convert.FromBase64String(trimmed);
                    }
                    else
                    {
                        return null;
                    }
                }

                string json = Encoding.UTF8.GetString(raw);
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                serializer.MaxJsonLength = int.MaxValue;
                object obj = serializer.DeserializeObject(json);
                IDictionary<string, object> root = obj as IDictionary<string, object>;
                if (root == null)
                {
                    return null;
                }

                MalleableProfile mp = new MalleableProfile();
                mp.V = ReadInt(root, "v", 0);
                mp.Sleep = ReadInt(root, "sleep", 60000);
                mp.Jitter = ReadInt(root, "jitter", 0);
                mp.Sections = new Dictionary<string, Section>();

                object sectionsObj;
                if (root.TryGetValue("sections", out sectionsObj))
                {
                    IDictionary<string, object> sectionsDict = sectionsObj as IDictionary<string, object>;
                    if (sectionsDict != null)
                    {
                        foreach (KeyValuePair<string, object> kv in sectionsDict)
                        {
                            Section section = ParseSection(kv.Value as IDictionary<string, object>);
                            if (section != null)
                            {
                                mp.Sections[kv.Key] = section;
                            }
                        }
                    }
                }

                return mp;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("MalleableProfile.Parse failed: " + ex.Message);
                return null;
            }
        }

        private static Section ParseSection(IDictionary<string, object> dict)
        {
            if (dict == null) return null;
            Section s = new Section();
            object clientObj;
            if (dict.TryGetValue("client", out clientObj))
            {
                s.Client = ParseClient(clientObj as IDictionary<string, object>);
            }
            object serverObj;
            if (dict.TryGetValue("server", out serverObj))
            {
                s.Server = ParseServer(serverObj as IDictionary<string, object>);
            }
            return s;
        }

        private static ClientSide ParseClient(IDictionary<string, object> dict)
        {
            if (dict == null) return null;
            ClientSide c = new ClientSide();
            c.Verb = ReadString(dict, "verb", "GET");
            c.Uris = ReadStringArray(dict, "uris");
            c.Headers = ReadStringDict(dict, "headers");
            c.Parameters = ReadStringDict(dict, "parameters");
            c.Body = ReadString(dict, "body", "");
            object metaObj;
            if (dict.TryGetValue("metadata", out metaObj))
            {
                c.Metadata = ParseContainer(metaObj as IDictionary<string, object>);
            }
            object outObj;
            if (dict.TryGetValue("output", out outObj))
            {
                c.Output = ParseContainer(outObj as IDictionary<string, object>);
            }
            return c;
        }

        private static ServerSide ParseServer(IDictionary<string, object> dict)
        {
            if (dict == null) return null;
            ServerSide s = new ServerSide();
            s.Headers = ReadStringDict(dict, "headers");
            s.BodyPrefix = ReadString(dict, "body_prefix", "");
            object outObj;
            if (dict.TryGetValue("output", out outObj))
            {
                s.Output = ParseContainer(outObj as IDictionary<string, object>);
            }
            return s;
        }

        private static Container ParseContainer(IDictionary<string, object> dict)
        {
            if (dict == null) return null;
            Container c = new Container();
            c.Transforms = new List<TransformOp>();
            object transformsObj;
            if (dict.TryGetValue("transforms", out transformsObj))
            {
                object[] arr = transformsObj as object[];
                if (arr != null)
                {
                    foreach (object item in arr)
                    {
                        IDictionary<string, object> td = item as IDictionary<string, object>;
                        if (td == null) continue;
                        TransformOp op = new TransformOp();
                        op.Op = ReadString(td, "op", "");
                        op.Value = ReadString(td, "value", "");
                        op.Key = ReadString(td, "key", "");
                        c.Transforms.Add(op);
                    }
                }
            }

            Terminator term = new Terminator();
            term.Type = "print";
            term.Arg = "";
            object termObj;
            if (dict.TryGetValue("terminator", out termObj))
            {
                IDictionary<string, object> td = termObj as IDictionary<string, object>;
                if (td != null)
                {
                    term.Type = ReadString(td, "type", "print");
                    term.Arg = ReadString(td, "arg", "");
                }
            }
            c.Terminator = term;
            return c;
        }

        private static int ReadInt(IDictionary<string, object> dict, string key, int fallback)
        {
            object v;
            if (!dict.TryGetValue(key, out v) || v == null) return fallback;
            if (v is int) return (int)v;
            if (v is long)
            {
                long l = (long)v;
                if (l > int.MaxValue) return int.MaxValue;
                if (l < int.MinValue) return int.MinValue;
                return (int)l;
            }
            if (v is double) return (int)(double)v;
            if (v is string)
            {
                int parsed;
                if (int.TryParse((string)v, out parsed)) return parsed;
            }
            return fallback;
        }

        private static string ReadString(IDictionary<string, object> dict, string key, string fallback)
        {
            object v;
            if (!dict.TryGetValue(key, out v) || v == null) return fallback;
            string s = v as string;
            return s ?? v.ToString();
        }

        private static string[] ReadStringArray(IDictionary<string, object> dict, string key)
        {
            object v;
            if (!dict.TryGetValue(key, out v) || v == null) return new string[0];
            object[] arr = v as object[];
            if (arr == null) return new string[0];
            List<string> list = new List<string>(arr.Length);
            foreach (object o in arr)
            {
                if (o == null) continue;
                string s = o as string;
                list.Add(s ?? o.ToString());
            }
            return list.ToArray();
        }

        private static Dictionary<string, string> ReadStringDict(IDictionary<string, object> dict, string key)
        {
            Dictionary<string, string> result = new Dictionary<string, string>();
            object v;
            if (!dict.TryGetValue(key, out v) || v == null) return result;
            IDictionary<string, object> inner = v as IDictionary<string, object>;
            if (inner == null) return result;
            foreach (KeyValuePair<string, object> kv in inner)
            {
                if (kv.Value == null) { result[kv.Key] = ""; continue; }
                string s = kv.Value as string;
                result[kv.Key] = s ?? kv.Value.ToString();
            }
            return result;
        }
    }

    public class Section
    {
        public ClientSide Client;
        public ServerSide Server;
    }

    public class ClientSide
    {
        public string Verb;
        public string[] Uris;
        public Dictionary<string, string> Headers;
        public Dictionary<string, string> Parameters;
        public string Body;
        public Container Metadata;
        public Container Output;
    }

    public class ServerSide
    {
        public Dictionary<string, string> Headers;
        public string BodyPrefix;
        public Container Output;
    }

    public class Container
    {
        public List<TransformOp> Transforms;
        public Terminator Terminator;
    }

    public class TransformOp
    {
        public string Op;
        public string Value;
        public string Key;
    }

    public class Terminator
    {
        public string Type;
        public string Arg;
    }
}
