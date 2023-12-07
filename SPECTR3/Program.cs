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
using System.Diagnostics;
using static SPECTR3.SP3DSK;
using DiskAccessLibrary;
using System.Reflection;

namespace SPECTR3
{

    internal class ISCSI_FORENSICS
    {

        public const string DefaultTargetIQN = "iqn.2023-05.io.alpine";

        private static int CreateISCSITarget(string drivename, List<Disk> m_disk, ISCSIServer m_server, string Hostname)
        {
            string txtTargetIQN;
            if (string.IsNullOrEmpty(Hostname))
            {
                txtTargetIQN = String.Format("{0}:{1}", DefaultTargetIQN, drivename);
            }
            else
            {
                txtTargetIQN = String.Format("{0}.{1}:{2}", DefaultTargetIQN, Hostname, drivename);
            }

            ISCSITarget m_target = new ISCSITarget(txtTargetIQN, m_disk);

            try
            {
                m_server.AddTarget(m_target);
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine(ex.Message, "Error");
                return 1;
            }

            return 0;
        }

        private static void PrintHelp()
        {
            Console.WriteLine("SPECTR3 v0.7 - Remote acquisition and forensic tool by Alpine Security");
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
            Console.WriteLine("  -a, --shareall");
            Console.WriteLine("    Share all disks.");
            Console.WriteLine("  -t, --timeout");
            Console.WriteLine("    Stop the service if the configured number of MINUTES without activity elapses. Ex. -t 60 (60 min)");
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
            Console.WriteLine("  --daemon");
            Console.WriteLine("    Run SPECTR3 as background unattended process. NOTE: Manually kill by PID needed.");
        }

        static int Main(string[] args)
        {
            bool list = false;
            bool thisegg = false;
            bool daemon = false;
            bool shareall = false;

            string thisip = string.Empty;
            string thisbind = string.Empty;
            string thisvolume = string.Empty;
            string thisdisk = string.Empty;

            string sshuser = string.Empty;
            string sshpass = string.Empty;
            string sshhost = string.Empty;

            string thisport;
            string thissshport;
            string thistimeout;

            int port = 3262;
            int sshport = 22;
            int timeout = 0;
            int pid;

            List<string> validargs = new List<string>()
                 { "--list", "--port", "--permitip", "--bindip", "--volume", "--disk", "--help", "--sshuser",
                   "--sshpass", "--sshhost", "--sshport", "--daemon", "--timeout", "--shareall", "-l", "-p",
                   "-i", "-b", "-h", "-v", "-d", "-a", "-o", "-t"};

            if (!SP3UTILS.SecurityHelper.IsAdministrator())
            {
                Console.WriteLine(" - Administrator privileges needed.");
                return 1;
            }

            for (int i = 0; i < args.Length; i++)
            {
                if (!validargs.Contains(args[i]) && args[i].StartsWith("-"))
                {
                    Console.WriteLine(" - ERROR: Invalid argument: " + args[i]);
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
                        Console.WriteLine("  - ERROR: Argument cannot be empty: " + args[i]);
                        return 1;
                    }

                    if (!SP3NET.ValidateIPv4(args[i + 1]))
                    {
                        Console.WriteLine("  - ERROR: Invalid Permited IP address");
                        return 1;
                    }

                    thisip = args[i + 1];
                }

                if (arg == "--bindip" || arg == "-b")
                {
                    if ((i + 1) >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                    {
                        Console.WriteLine("  - ERROR: Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                    thisbind = args[i + 1];

                    if (SP3NET.CheckIP(thisbind) == false)
                    {
                        Console.WriteLine("  - ERROR: Invalid Bind IP address");
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
                        Console.WriteLine("  - ERROR: Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                }

                if (arg == "--volume" || arg == "-v")
                {
                    if ((i + 1) >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                    {
                        Console.WriteLine("  - ERROR: Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                    thisvolume = args[i + 1];
                }

                if (arg == "--disk" || arg == "-d")
                {
                    if ((i + 1) >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                    {
                        Console.WriteLine("  - ERROR: Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                    thisdisk = args[i + 1];
                }

                if (arg == "--shareall" || arg == "-a")
                {
                    shareall = true;
                }

                if (arg == "-o")
                {
                    thisegg = true;
                }

                if (arg == "--sshuser")
                {
                    if ((i + 1) >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                    {
                        Console.WriteLine("  - ERROR: Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                    sshuser = args[i + 1];
                }

                if (arg == "--sshpass")
                {
                    if ((i + 1) >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                    {
                        Console.WriteLine("  - ERROR: Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                    sshpass = args[i + 1];
                }

                if (arg == "--sshhost")
                {
                    if ((i + 1) >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                    {
                        Console.WriteLine("  - ERROR: Argument cannot be empty: " + args[i]);
                        return 1;
                    }

                    if (!SP3NET.ValidateIPv4(args[i + 1]))
                    {
                        Console.WriteLine("  - ERROR: Invalid SSH IP address");
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
                        Console.WriteLine("  - ERROR: Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                }
                if (arg == "--timeout" || arg == "-t")
                {
                    thistimeout = args[i + 1];
                    if (!string.IsNullOrEmpty(thistimeout))
                    {
                        timeout = Conversion.ToInt32(thistimeout);
                        //Convert timeout from min to seconds
                        timeout *= 60;
                        ISCSIServer.toactivate = true;
                        ISCSIServer.toinitvalue = timeout;
                    }
                    else
                    {
                        Console.WriteLine("  - ERROR: Argument cannot be empty: " + args[i]);
                        return 1;
                    }
                }
            }

            // These arguments have to be checked after other previously checked arguments.
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--daemon")
                {
                    daemon = true;
                }
                
                if (!string.IsNullOrEmpty(sshhost) && daemon)
                {
                    if (string.IsNullOrEmpty(sshpass) || string.IsNullOrEmpty(sshuser))
                    {
                        Console.WriteLine("  - ERROR: If --daemon and --sshhost are provided, --sshuser and --sshpass arguments are required.");
                        return 1;
                    }
                }
            }

            if ((string.IsNullOrEmpty(thisvolume) && string.IsNullOrEmpty(thisdisk)) && !list && !shareall)
            {
                PrintHelp();
                return 1;
            }

            //Initiatize values
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

                (sshuser, sshpass) = SP3UTILS.GetSshUserAndPassword(sshuser, sshpass);
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
            String Hostname = Dns.GetHostName().ToLower();

            string drivename = String.Empty;
            //Initialize m_disk with the selected volume or disk
            txtTargetIQN = String.Format("Muti-Targets");
            if (shareall)
            {
                int dskindex = 0;

                while (SP3DSK.IsDiskIndexValid(dskindex))
                {
                    PhysicalDisk disk = SP3DSK.GetDiskByIndex(dskindex);
                    CreateISCSITarget(String.Format("dsk{0}", dskindex), new List<Disk>() { disk }, m_server, Hostname);
                    dskindex++;
                }
            }
            else if (!string.IsNullOrEmpty(thisvolume))
            {
                if (!SP3DSK.IsVolumeIndexValid(Conversion.ToInt32(thisvolume)))
                {
                    Console.WriteLine("  - Invalid volume index", "Error");
                    return 1;
                }
                int volindex = Conversion.ToInt32(thisvolume);
                drivename = String.Format("vol{0}", thisvolume);
                VolumeDisk volume = SP3DSK.GetVolumeByIndex(volindex);
                CreateISCSITarget(drivename, new List<Disk>() { volume }, m_server, Hostname);
                txtTargetIQN = String.Format("{0}.{1}:{2}", DefaultTargetIQN, Hostname, drivename);

            }
            else if (!string.IsNullOrEmpty(thisdisk))
            {
                if (!SP3DSK.IsDiskIndexValid(Conversion.ToInt32(thisdisk)))
                {
                    Console.WriteLine("  - Invalid disk index", "Error");
                    return 1;
                }
                int dskindex = Conversion.ToInt32(thisdisk);
                drivename = String.Format("dsk{0}", thisdisk);
                PhysicalDisk disk = SP3DSK.GetDiskByIndex(dskindex);
                CreateISCSITarget(drivename, new List<Disk>() { disk }, m_server, Hostname);
                txtTargetIQN = String.Format("{0}.{1}:{2}", DefaultTargetIQN, Hostname, drivename);
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

            //Daemon mode
            if (daemon)
            {
                string argsString = string.Join(" ", args);
                if (argsString.Contains("--daemon"))
                {
                    argsString = argsString.Replace("--daemon", "");
                }
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = "SPECTR3.exe";
                startInfo.Arguments = argsString;
                startInfo.CreateNoWindow = true;
                startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                startInfo.RedirectStandardOutput = true;
                startInfo.UseShellExecute = false;
                Process process = Process.Start(startInfo);
                //Get PID of the background process
                pid = process.Id;

                //Print Server Info
                Console.WriteLine();
                Console.WriteLine("  - SPECTR3 Server running in background PID (" + pid + ") at "
                                       + serverAddress + ":" + port);
                Console.WriteLine("    + Target IQN: " + txtTargetIQN);
                Console.WriteLine("    + Access Permited from: " + permitedAddress.ToString());
                return 0;
            }

            //Print Server Info
            Console.WriteLine();
            Console.WriteLine("  - SPECTR3 Server running at " + serverAddress + ":" + port);
            Console.WriteLine("    + Target IQN: " + txtTargetIQN);
            Console.WriteLine("    + Access Permited from: " + permitedAddress.ToString());

            if (ISCSIServer.toactivate)
            {
                Console.WriteLine("    + Timeout: " + timeout + " seconds");
                ISCSIServer.toglobal = timeout;
                ISCSIServer.toswitch = true;
            }

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
                //if timeout is set, subtract 2 seconds to ISCSIServer.toglobal
                if (ISCSIServer.toswitch)
                {
                    if (ISCSIServer.toglobal == 0)
                    {
                        sp3Server.StopServer();
                        return 0;
                    }
                    ISCSIServer.toglobal -= 2;
                }
                Thread.Sleep(2000);
            }
            
        }
    }
}
