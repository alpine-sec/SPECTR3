﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using DiskAccessLibrary;
using DiskAccessLibrary.LogicalDiskManager;
using DiskAccessLibrary.Win32;
using System.Reflection;

namespace SPECTR3
{
    public class SP3DSK
    {
        public static void ShowDiskAndVolumes()
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

        public static bool IsDiskIndexValid(int diskIndex)
        {
            List<PhysicalDisk> physicalDisks = PhysicalDiskHelper.GetPhysicalDisks();
            return physicalDisks.Any(disk => disk.PhysicalDiskIndex == diskIndex);
        }

        public static bool IsVolumeIndexValid(int volumeIndex)
        {
            List<Volume> volumes = WindowsVolumeHelper.GetVolumes();
            return volumeIndex >= 0 && volumeIndex < volumes.Count;
        }

        public static PhysicalDisk GetDiskByIndex(int diskIndex)
        {
            PhysicalDisk selectedDisk = null;
            List<PhysicalDisk> physicalDisks = PhysicalDiskHelper.GetPhysicalDisks();
            foreach (PhysicalDisk physicalDisk in physicalDisks)
            {
                if (physicalDisk.PhysicalDiskIndex == diskIndex)
                {
                    selectedDisk = new PhysicalDisk(physicalDisk.PhysicalDiskIndex, true);
                    break;
                }
            }
            return selectedDisk;
        }

        public static VolumeDisk GetVolumeByIndex(int volindex)
        {
            VolumeDisk volumeDisk = null;
            List<Volume> volumes = WindowsVolumeHelper.GetVolumes();
            for (int index = 0; index < volumes.Count; index++)
            {
                if (index == volindex)
                {
                    Volume volume = volumes[index];
                    volumeDisk = new VolumeDisk(volume, true);
                    break;
                }
            }
            return volumeDisk;
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
                string sizeString = SP3UTILS.BytesToString(physicalDisk.Size);

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

                string thisSizeString = SP3UTILS.BytesToString(volume.Size);
                string line = $"    + {title}:  {name} {type} {thisSizeString} {status}";
                volumeList.Add(line);
            }

            return volumeList;
        }

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

    }
    public class SP3UTILS
    {

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
                                               "We need a mind blowing presentation",
                                               "Nobody told me the code had to be secure"};
            Random rnd = new Random();
            int index = rnd.Next(messages.Length);
            return messages[index];
        }

        public static String BytesToString(long byteCount)
        {
            string[] suf = { "B", "KB", "MB", "GB", "TB", "PB", "EB" }; //Longs run out around EB
            if (byteCount == 0)
                return "0" + suf[0];
            long bytes = Math.Abs(byteCount);
            int place = Convert.ToInt32(Math.Floor(Math.Log(bytes, 1024)));
            double num = Math.Round(bytes / Math.Pow(1024, place), 1);
            return (Math.Sign(byteCount) * num).ToString() + suf[place];
        }

        public static (string, string) GetSshUserAndPassword(string sshuser = null, string sshpass = null)
        {
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
                if (SP3UTILS.IsBase64String(sshpass))
                {
                    sshpass = SP3UTILS.Base64Decode(sshpass).TrimEnd('\r', '\n'); ;
                }
                else
                {
                    Console.WriteLine("    + Error: SSH Password is not base64 encoded");
                    Environment.Exit(1);
                }
            }

            return (sshuser, sshpass);
        }

    }
    public class SP3NET
    {
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

        // Check if a dns like "shaw.alpinesec.cloud" is valid
        public static bool ValidateDNS(string dns)
        {
            bool isValid = false;
            try
            {
                IPHostEntry host = Dns.GetHostEntry(dns);
                isValid = true;
            }
            catch (Exception)
            {
                isValid = false;
            }
            return isValid;
        }
    }
}
