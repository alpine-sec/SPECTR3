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
using System.Collections.Generic;
using System.Net.Sockets;
using System.Net;
using DiskAccessLibrary.Win32;
using Utilities;
using ISCSI.Server;
using System.Threading;

namespace SPECTR3
{

    internal class ISCSI_FORENSICS
    {

        public const string DefaultTargetIQN = "iqn.2023-05.io.alpine";

        private static void PrintHelp()
        {
            Console.WriteLine("SPECTR3 v0.4.6 - Remote acquisition and forensic tool by Alpine Security");
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

            if (!SP3UTILS.SecurityHelper.IsAdministrator())
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
                    SP3DSK.ShowDiskAndVolumes();
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

                    if (!SP3NET.ValidateIPv4(args[i + 1]))
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

                    if (SP3NET.CheckIP(thisbind) == false)
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

                    if (!SP3NET.ValidateIPv4(args[i + 1]))
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
                    if (SP3UTILS.IsBase64String(sshpass))
                    {
                        sshpass = SP3UTILS.Base64Decode(sshpass).TrimEnd('\r', '\n'); ;
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
                    serverIP = SP3NET.GetLocalIPAddress();
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
                SP3DSK.VolumeDisk volumeDisk;
                List<Volume> volumes = WindowsVolumeHelper.GetVolumes();
                for (int index = 0; index < volumes.Count; index++)
                {
                    if (index == volindex)
                    {
                        Volume volume = volumes[index];
                        volumeDisk = new SP3DSK.VolumeDisk(volume, true);
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
            String Hostname = Dns.GetHostName().ToLower();
            if (string.IsNullOrEmpty(Hostname))
            {
                txtTargetIQN = String.Format("{0}:{1}", DefaultTargetIQN, drivename);
            }
            else
            {
                txtTargetIQN = String.Format("{0}.{1}:{2}", DefaultTargetIQN, Hostname, drivename);
            }

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

            //Print MOTD
            if (thisegg)
            {
                Console.WriteLine();
                Console.WriteLine("  - Funny MOTD: " + SP3UTILS.GetRandomMessage());
            }

            //Print Server Info
            Console.WriteLine();
            Console.WriteLine("  - SPECTR3 Server running at " + serverAddress + ":" + port);
            Console.WriteLine("    + Target IQN: " + txtTargetIQN);
            Console.WriteLine("    + Access Permited from: " + permitedAddress.ToString());

            //Start Server
            Sp3Server sp3Server = new Sp3Server(m_server, serverAddress, port, permitedAddress,
                                    sshhost, sshport, sshuser, sshpass);
            try
            {
                sp3Server.Start();
            }
            catch (SocketException ex)
            {
                Console.WriteLine("  - Cannot start server, " + ex.Message, "Error");
                return 1;
            }

            //Wait until user press enter
            Console.WriteLine("  - Press ENTER key to stop sharing and close server ...  ");
            while (true)
            {
                if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Enter)
                {
                    sp3Server.StopServer();
                    return 0;
                }
                Thread.Sleep(2000);
            }
            
        }
    }
}
