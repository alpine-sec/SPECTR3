/* (c) Author: Miguel Quero (KeRo99)
 * 
 * E-mail: miguel.quero@alpinesec.io
 * Company: Alpine Security
 * 
 * Special Thanks to:
 *    - Tal Aloni for his work on iSCSI-Console
 *    - Borja Merino for his help with C#
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */


using System;
using System.Text;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Net;
using System.Net.NetworkInformation;
using DiskAccessLibrary;
using DiskAccessLibrary.LogicalDiskManager;
using DiskAccessLibrary.Win32;
using Utilities;
using ISCSI.Server;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Reflection;
using System.Linq;

namespace SPECTR3
{

    internal class ISCSI_FORENSICS
    {

        public const string DefaultTargetIQN = "iqn.2023-05.io.alpine";

        public class VolumeDisk : Disk // a fake disk that serves a single volume
        {
            private Volume m_volume;
            private bool m_isReadOnly;

            public VolumeDisk(Volume volume, bool isReadOnly)
            {
                m_volume = volume;
                m_isReadOnly = volume.IsReadOnly || isReadOnly;
            }

            public override byte[] ReadSectors(long sectorIndex, int sectorCount)
            {
                return m_volume.ReadSectors(sectorIndex, sectorCount);
            }

            public override void WriteSectors(long sectorIndex, byte[] data)
            {
                if (!IsReadOnly)
                {
                    m_volume.WriteSectors(sectorIndex, data);
                }
            }

            public override int BytesPerSector
            {
                get
                {
                    return m_volume.BytesPerSector;
                }
            }

            public override long Size
            {
                get
                {
                    return m_volume.Size;
                }
            }

            public override bool IsReadOnly
            {
                get
                {
                    return m_isReadOnly;
                }
            }

            public Volume Volume
            {
                get
                {
                    return m_volume;
                }
            }
        }

        public class SecurityHelper
        {
            public static bool IsAdministrator()
            {
                WindowsIdentity windowsIdentity = null;
                try
                {
                    windowsIdentity = WindowsIdentity.GetCurrent();
                }
                catch
                {
                    return false;
                }
                WindowsPrincipal windowsPrincipal = new WindowsPrincipal(windowsIdentity);
                return windowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        public static bool IsBase64String(String s)
        {
            s = s.Trim();
            return (s.Length % 4 == 0) && Regex.IsMatch(s, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);

        }

        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return Encoding.UTF8.GetString(base64EncodedBytes);
        }

        // Get random phrases from a messages list
        public static string GetRandomMessage()
        {
            string[] messages = new string[] { "What's the problem with having meetings at 3 a.m.?",
                                               "I invented that 10 years ago",
                                               "Furest already does",
                                               "Trinito already does",
                                               "The infrastructure never falls off",
                                               "Cool EVERYTHING",
                                               "My twitter profile on the front page!",
                                               "That's not how we do things here",
                                               "Automate, Automate, Automate!",
                                               "Real World",
                                               "Not Trivial",
                                               "We have to show our chest",
                                               "This is a game changer",
                                               "This was born after a brain storm meeting at 3 am",
                                               "Is this Cloud free?",
                                               "This tool was designed 10 years ago",
                                               "This is the result of years of automation",
                                               "I'll take this in one night",
                                               "It is just a IF",
                                               "We need a mind blowing presentation "};
            Random rnd = new Random();
            int index = rnd.Next(messages.Length);
            return messages[index];
        }

        //Get the interface ip address with gateway and not localhost
        public static string GetLocalIPAddress()
        {
            string ipaddress = "";
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet && ni.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (GatewayIPAddressInformation gipi in ni.GetIPProperties().GatewayAddresses)
                    {
                        if (gipi.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            ipaddress = ni.GetIPProperties().UnicastAddresses[1].Address.ToString();
                        }
                    }
                }
                // Get the interface ip address for wifi conections if ethernet is not available
                if (string.IsNullOrEmpty(ipaddress) && ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 && ni.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (GatewayIPAddressInformation gipi in ni.GetIPProperties().GatewayAddresses)
                    {
                        if (gipi.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            ipaddress = ni.GetIPProperties().UnicastAddresses[1].Address.ToString();
                        }
                    }
                }
            }
            return ipaddress;
        }

        public static bool CheckIP(string ipAddress)
        {
            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Ethernet && networkInterface.OperationalStatus == OperationalStatus.Up ||
                    networkInterface.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 && networkInterface.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (UnicastIPAddressInformation ipInfo in networkInterface.GetIPProperties().UnicastAddresses)
                    {
                        if (ipInfo.Address.AddressFamily == AddressFamily.InterNetwork &&
                            IPAddress.Parse(ipAddress).Equals(ipInfo.Address))
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        public static bool ValidateIPv4(string ip)
        {
            IPAddress address;
            return ip != null && ip.Count(c => c == '.') == 3 &&
                IPAddress.TryParse(ip, out address);
        }

        static String BytesToString(long byteCount)
        {
            string[] suf = { "B", "KB", "MB", "GB", "TB", "PB", "EB" }; //Longs run out around EB
            if (byteCount == 0)
                return "0" + suf[0];
            long bytes = Math.Abs(byteCount);
            int place = Convert.ToInt32(Math.Floor(Math.Log(bytes, 1024)));
            double num = Math.Round(bytes / Math.Pow(1024, place), 1);
            return (Math.Sign(byteCount) * num).ToString() + suf[place];
        }

        public static List<string> VolumesList()
        {
            List<string> volumeList = new List<string>();

            List<Volume> volumes = WindowsVolumeHelper.GetVolumes();
            for (int i = 0; i < volumes.Count; i++)
            {
                Volume volume = volumes[i];
                string title = String.Format("Vol {0}", i);
                string type = VolumeHelper.GetVolumeTypeString(volume);
                string status = VolumeHelper.GetVolumeStatusString(volume);

                ulong volumeID = 0;
                string name = String.Empty;

                if (volume is DynamicVolume)
                {
                    var dynamicVolume = (DynamicVolume)volume;
                    volumeID = dynamicVolume.VolumeID;
                    name = dynamicVolume.Name;
                }
                else if (volume is GPTPartition)
                {
                    name = ((GPTPartition)volume).PartitionName;
                }

                if (string.IsNullOrEmpty(name))
                {
                    name = "Noname";
                }

                string thisSizeString = BytesToString(volume.Size);
                string line = $"    + {title}:  {name} {type} {thisSizeString} {status}";
                volumeList.Add(line);
            }

            return volumeList;
        }

        static List<string> DiskList()
        {
            List<string> dskstr = new List<string>();
            List<PhysicalDisk> physicalDisks = PhysicalDiskHelper.GetPhysicalDisks();
            foreach (PhysicalDisk physicalDisk in physicalDisks)
            {
                string title = String.Format("Dsk {0}", physicalDisk.PhysicalDiskIndex);
                string description = physicalDisk.Description;
                string serialNumber = physicalDisk.SerialNumber;
                string sizeString = BytesToString(physicalDisk.Size);

                string status = string.Empty;
                string line;
                try
                {
                    if (Environment.OSVersion.Version.Major > 6)
                    {
                        bool isOnline = physicalDisk.GetOnlineStatus();
                        status = isOnline ? "Online" : "Offline";

                    }
                    
                }
                catch (Exception)
                {
                    status = "Unknown";
                }
                line = string.Format("    + {0}:  {1}  {2}  {3}  {4}", title, description, serialNumber, sizeString, status);
                dskstr.Add(line);
            }
            return dskstr;
        }



        static void ShowDiskAndVolumes()
        {
            List<string> volstr;
            List<string> dskstr;
            Console.WriteLine("- List Physical Disks:");
            dskstr = DiskList();
            foreach (string dsk in dskstr)
            {
                Console.WriteLine(dsk);
            }
            Console.WriteLine("- List Volumes:");
            volstr = VolumesList();
            foreach (string vol in volstr)
            {
                Console.WriteLine(vol);
            }
        }

        private static void PrintHelp()
        {
            Console.WriteLine("SPECTR3 v0.4.3 - Remote acquisition and forensic tool by Alpine Security");
            Console.WriteLine("Usage: SPECTR3.exe [options]");
            Console.WriteLine("Options:");
            Console.WriteLine("  -l, --list");
            Console.WriteLine("    List available volumes and disks.");
            Console.WriteLine("  -p, --port");
            Console.WriteLine("    Set the port number to listen on.");
            Console.WriteLine("  -i, --permitip");
            Console.WriteLine("    Set the permited ip client to connect.");
            Console.WriteLine("  -b, --bindip");
            Console.WriteLine("    Set the bind ip where server will listen.");
            Console.WriteLine("  -v, --volume");
            Console.WriteLine("    Set the volume to share.");
            Console.WriteLine("  -d, --disk");
            Console.WriteLine("    Set the disk to share.");
            Console.WriteLine("  -h, --help");
            Console.WriteLine("    Print this help message.");
            Console.WriteLine("  --sshuser");
            Console.WriteLine("    Set the ssh user to connect.");
            Console.WriteLine("  --sshpass");
            Console.WriteLine("    Set the ssh password to connect in BASE64. NOTE: if the password is empty, the prompt will ask for the password, in this case it does not need to be entered in BASE64.");
            Console.WriteLine("  --sshhost");
            Console.WriteLine("    Set the ssh host to connect.");
            Console.WriteLine("  --sshport");
            Console.WriteLine("    Set the ssh port to connect. Default: 22");
                
        }

        static int Main(string[] args)
        {
            bool list = false;
            bool thisegg = false;

            string thisip = string.Empty;
            string thisbind = string.Empty;
            string thisvolume = string.Empty;
            string thisdisk = string.Empty;

            string sshuser = string.Empty;
            string sshpass = string.Empty;
            string sshhost = string.Empty;

            string thisport;
            string thissshport;

            int port = 3262;
            int sshport = 22;

            List<string> validargs = new List<string>()
                 { "--list", "--port", "--permitip", "--bindip", "--volume", "--disk", "--help", "--sshuser",
                   "--sshpass", "--sshhost", "--sshport", "-l", "-p", "-i", "-b", "-h", "-v", "-d", "-o"};

            if (!SecurityHelper.IsAdministrator())
            {
                Console.WriteLine(" - Administrator privileges needed.");
                return 1;
            }

            for (int i = 0; i < args.Length; i++)
            {
                if (!validargs.Contains(args[i]) && args[i].StartsWith("-"))
                {
                    Console.WriteLine(" - Invalid argument: " + args[i]);
                    return 1;
                }

                var arg = args[i].ToLower();

                if (arg == "--list" || arg == "-l")
                {
                    list = true;
                    ShowDiskAndVolumes();
                    return 0;
                }

                if (arg == "--help" || arg == "-h")
                {
                    PrintHelp();
                    return 0;
                }

                if (arg == "--permitip" || arg == "-i")
                {
                    if ((i + 1) >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                    {
                        Console.WriteLine("  - Argument cannot be empty: " + args[i]);
                        return 1;
                    }

                    if (!ValidateIPv4(args[i + 1]))
                    {
                        Console.WriteLine("  - Invalid Permited IP address");
                        return 1;
                    }

                    thisip = args[i + 1];
                }

                if (arg == "--bindip" || arg == "-b")
                {
                    if ((i + 1) >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                    {
                        Console.WriteLine("  - Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                    thisbind = args[i + 1];

                    if (CheckIP(thisbind) == false)
                    {
                        Console.WriteLine("  - Invalid Bind IP address");
                        return 1;
                    }
                }

                if (arg == "--port" || arg == "-p")
                {
                    thisport = args[i + 1];
                    if (!string.IsNullOrEmpty(thisport))
                    {
                        port = Conversion.ToInt32(thisport);
                    }
                    else
                    {
                        Console.WriteLine("  - Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                }

                if (arg == "--volume" || arg == "-v")
                {
                    if ((i + 1) >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                    {
                        Console.WriteLine("  - Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                    thisvolume = args[i + 1];
                }

                if (arg == "--disk" || arg == "-d")
                {
                    if ((i + 1) >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                    {
                        Console.WriteLine("  - Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                    thisdisk = args[i + 1];
                }

                if (arg == "-o")
                {
                    thisegg = true;
                }

                if (arg == "--sshuser")
                {
                    if ((i + 1) >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                    {
                        Console.WriteLine("  - Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                    sshuser = args[i + 1];
                }

                if (arg == "--sshpass")
                {
                    if ((i + 1) >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                    {
                        Console.WriteLine("  - Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                    sshpass = args[i + 1];
                }

                if (arg == "--sshhost")
                {
                    if ((i + 1) >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                    {
                        Console.WriteLine("  - Argument cannot be empty: " + args[i]);
                        return 1;
                    }

                    if (!ValidateIPv4(args[i + 1]))
                    {
                        Console.WriteLine("  - Invalid SSH IP address");
                        return 1;
                    }
                    sshhost = args[i + 1];
                }

                if (arg == "--sshport")
                {
                    thissshport = args[i + 1];
                    if (!string.IsNullOrEmpty(thissshport))
                    {
                        sshport = Conversion.ToInt32(thissshport);
                    }
                    else
                    {
                        Console.WriteLine("  - Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                }
            }

            if ((string.IsNullOrEmpty(thisvolume) && string.IsNullOrEmpty(thisdisk)) && !list)
            {
                PrintHelp();
                return 1;
            }


            //Initiatize values
            ISCSITarget m_target;
            List<Disk> m_disks = new List<Disk>();
            string txtTargetIQN;

            //Initialize Network parameters
            IPAddress permitedAddress = IPAddress.Any;
            IPAddress serverAddress;
            String serverIP;

            if (!string.IsNullOrEmpty(sshhost))
            {
                serverAddress = IPAddress.Loopback;
                permitedAddress = IPAddress.Loopback;
            
                if (string.IsNullOrEmpty(sshuser))
                {
                    //get sshuser by prompt
                    Console.Write("  - SSH Username: ");
                    sshuser = Console.ReadLine();
                }

                if (string.IsNullOrEmpty(sshpass))
                {
                    //get sshuser by prompt
                    Console.Write("  - SSH Password: ");
                    ConsoleKeyInfo keyInfo;
                    do
                    {
                        keyInfo = Console.ReadKey(true);
                        // Skip if Backspace or Enter is Pressed
                        if (keyInfo.Key != ConsoleKey.Backspace && keyInfo.Key != ConsoleKey.Enter)
                        {
                            sshpass += keyInfo.KeyChar;
                            Console.Write("*");
                        }
                        else
                        {
                            if (keyInfo.Key == ConsoleKey.Backspace && sshpass.Length > 0)
                            {
                                // Remove last character if Backspace is Pressed
                                sshpass = sshpass.Substring(0, (sshpass.Length - 1));
                                Console.Write("\b \b");
                            }
                        }
                    }
                    // Stops Getting Password Once Enter is Pressed
                    while (keyInfo.Key != ConsoleKey.Enter);
                }
                else
                {
                    //Check if sshpass is base64 encoded
                    if (IsBase64String(sshpass))
                    {
                        sshpass = Base64Decode(sshpass).TrimEnd('\r', '\n'); ;
                    }
                    else
                    {
                        Console.WriteLine("    + Error: SSH Password is not base64 encoded");
                        return 1;
                    }

                }
            }
            else
            {

                try
                {
                    serverIP = GetLocalIPAddress();
                }
                catch
                {
                    serverIP = string.Empty;
                }

                if (!string.IsNullOrEmpty(thisbind))
                {
                    serverAddress = IPAddress.Parse(thisbind);
                }
                else
                {
                    if (string.IsNullOrEmpty(serverIP))
                    {
                        serverAddress = IPAddress.Any;
                    }
                    else
                    {
                        serverAddress = IPAddress.Parse(serverIP);
                    }
                }
                if (!string.IsNullOrEmpty(thisip))
                {
                    // Change the Permited IP Address global value
                    permitedAddress = IPAddress.Parse(thisip);
                }
            }


            ISCSIServer m_server = new ISCSIServer(permitedAddress);
            string drivename = String.Empty;

            //Initialize m_disk with the selected volume or disk
            if (!string.IsNullOrEmpty(thisvolume))
            {
                int volindex = Conversion.ToInt32(thisvolume);
                drivename = String.Format("vol{0}", thisvolume);
                VolumeDisk volumeDisk;
                List<Volume> volumes = WindowsVolumeHelper.GetVolumes();
                for (int index = 0; index < volumes.Count; index++)
                {
                    if (index == volindex)
                    {
                        Volume volume = volumes[index];
                        volumeDisk = new VolumeDisk(volume, true);
                        // Add the volume to the list of disks to share
                        m_disks.Add(volumeDisk);
                        break;
                    }
                }
            }
            else if (!string.IsNullOrEmpty(thisdisk))
            {
                int dskindex = Conversion.ToInt32(thisdisk);
                drivename = String.Format("dsk{0}", thisdisk);
                PhysicalDisk selectedDisk;
                List<PhysicalDisk> physicalDisks = PhysicalDiskHelper.GetPhysicalDisks();
                foreach (PhysicalDisk physicalDisk in physicalDisks)
                {
                    if (physicalDisk.PhysicalDiskIndex == dskindex)
                    {
                        selectedDisk = new PhysicalDisk(physicalDisk.PhysicalDiskIndex, true);
                        m_disks.Add(selectedDisk);
                        break;
                    }
                }
            }

            txtTargetIQN = String.Format("{0}:{1}", DefaultTargetIQN, drivename);
            m_target = new ISCSITarget(txtTargetIQN, m_disks);


            try
            {
                m_server.AddTarget(m_target);
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine(ex.Message, "Error");
                return 1;
            }

            if (port <= 0 || port > UInt16.MaxValue)
            {
                Console.WriteLine("  - Invalid TCP port", "Error");
                return 1;
            }

            IPEndPoint endpoint = new IPEndPoint(IPAddress.Any, port);
            try
            {
                m_server.Start(endpoint);
                Console.WriteLine();
                if (thisegg)
                {
                    Console.WriteLine("  - Funny MOTD: " + GetRandomMessage());
                    Console.WriteLine();
                }

                Console.WriteLine("  - SPECTR3 Server running at " + serverAddress + ":" + port);
                Console.WriteLine("    + Access Permited from: " + permitedAddress.ToString());

                if (!string.IsNullOrEmpty(sshhost))
                {
                    SPECTR3SSH ssh = new SPECTR3SSH();
                    ssh.StartSshReverseTunnel(sshhost, sshport, sshuser, sshpass, (uint)port);
                }

            }

            catch (SocketException ex)
            {
                Console.WriteLine("  - Cannot start server, " + ex.Message, "Error");
                return 1;
            }

            // Does not close the console window
            Console.WriteLine("  - Press any key to stop sharing and close server ...  ");
            Console.ReadLine();
            m_server.Stop();
            Console.WriteLine("    + Server stopped. Bye");

            return 0;
        }
    }
}
