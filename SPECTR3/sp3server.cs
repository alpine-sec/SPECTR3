using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using ISCSI.Server;

namespace SPECTR3
{
    internal class Sp3Server
    {
        private readonly ISCSIServer m_server;
        private readonly IPAddress serverAddress;
        private readonly int port;
        private readonly IPAddress permitedAddress;
        private readonly string sshhost;
        private readonly int sshport;
        private readonly string sshuser;
        private readonly string sshpass;

        public Sp3Server(ISCSIServer m_server, IPAddress serverAddress, int port, IPAddress permitedAddress,
                                               string sshhost, int sshport, string sshuser, string sshpass)
        {
            this.m_server = m_server;
            this.serverAddress = serverAddress;
            this.port = port;
            this.permitedAddress = permitedAddress;
            this.sshhost = sshhost;
            this.sshport = sshport;
            this.sshuser = sshuser;
            this.sshpass = sshpass;
        }

        private void DisconnectSsh(SPECTR3SSH ssh)
        {
            // Close SSH tunnel if it was created
            if (ssh != null)
            {
                ssh.Disconnect();
            }
        }

        private void StopServer()
        {
            m_server.Stop();
            Console.WriteLine("  - SPECTR3 Server stopped. Bye");
        }

        public int Start()
        {
            //Start Server
            IPEndPoint endpoint = new IPEndPoint(serverAddress, port);
            try
            {
                m_server.Start(endpoint);
            }
            catch (SocketException ex)
            {
                Console.WriteLine("  - Cannot start server, " + ex.Message, "Error");
                return 1;
            }
            Console.WriteLine();

            //Print Server Info
            Console.WriteLine("  - SPECTR3 Server running at " + serverAddress + ":" + port);
            Console.WriteLine("    + Access Permited from: " + permitedAddress.ToString());
            Console.WriteLine("  - Press ENTER key to stop sharing and close server ...  ");

            //Print SSH Tunnel Info
            SPECTR3SSH ssh = null;
            if (!string.IsNullOrEmpty(sshhost))
            {
                int retries = 0;
                bool StopServer = false;
                ssh = new SPECTR3SSH(sshhost, sshport, sshuser, sshpass, (uint)port);
                Console.WriteLine("  - Connecting to SSH server ...");
                while (!StopServer || retries > 5)
                {
                    // Check if the ssh connection state is not connected
                    if (!ssh.IsConnected)
                    {
                        try
                        {
                            if (retries > 0)
                            {
                                ssh = new SPECTR3SSH(sshhost, sshport, sshuser, sshpass, (uint)port);
                                ssh.Connect();
                                Console.WriteLine("    + SSH connection state: Re-Connected");
                            }
                            else
                            {
                                ssh.Connect();
                                Console.WriteLine("    + SSH connection state: Connected");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("    + Error connecting to SSH server: " + ex.Message);
                            retries++;
                            Console.WriteLine("    + Retrying in 10 seconds ... {0}/5", retries);
                            Thread.Sleep(10000);

                        }
                    }
                    if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Enter)
                    {
                        StopServer = true;
                    }
                    Thread.Sleep(1000);
                }
            }
            else
            {
                while (true)
                {
                    if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Enter)
                    {
                        break;
                    }
                }

            }

            DisconnectSsh(ssh);
            StopServer();

            return 0;
        }
    }
}
