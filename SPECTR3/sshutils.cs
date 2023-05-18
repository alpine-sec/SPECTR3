using Renci.SshNet;
using System;

namespace SPECTR3
{
    internal class SPECTR3SSH
    {
        private readonly SshClient sshClient;
        private readonly ForwardedPortRemote fwdPort;

        public SPECTR3SSH(string sshHost, int sshPort, string sshUser, string sshPass, uint dstPort)
        {
            ConnectionInfo connInfo = new ConnectionInfo(sshHost, sshPort, sshUser, new AuthenticationMethod[] { new PasswordAuthenticationMethod(sshUser, sshPass) });
            sshClient = new SshClient(connInfo);
            sshClient.KeepAliveInterval = TimeSpan.FromSeconds(30);
            sshClient.ConnectionInfo.Timeout = TimeSpan.FromSeconds(20);

            fwdPort = new ForwardedPortRemote(dstPort, "127.0.0.1", dstPort);
        }

        public bool IsConnected { get { return sshClient.IsConnected; } }

        public ConnectionState ConnectionState { get { return IsConnected ? ConnectionState.Connected : ConnectionState.Disconnected; } }

        public void Connect()
        {
            if (!sshClient.IsConnected)
            {
                sshClient.Connect();

                if (sshClient.IsConnected)
                {
                    sshClient.AddForwardedPort(fwdPort);
                    fwdPort.Exception += (sender, e) =>
                    {
                        Console.WriteLine("    + Error forwarding port: {0}", e.Exception);
                    };
                    fwdPort.Start();
                    Console.WriteLine("    + SSH tunnel successfully connected to {0}:{1}", sshClient.ConnectionInfo.Host, sshClient.ConnectionInfo.Port);
                }
            }
            else
            {
                Console.WriteLine("    + SSH tunnel is already connected to {0}:{1}", sshClient.ConnectionInfo.Host, sshClient.ConnectionInfo.Port);
            }
        }

        public void Disconnect()
        {
            if (sshClient.IsConnected)
            {
                fwdPort.Stop();
                sshClient.Disconnect();
                Console.WriteLine("    + SSH tunnel disconnected.");
            }
            else
            {
                Console.WriteLine("    + SSH tunnel is already disconnected.");
            }
        }
    }
    public enum ConnectionState
    {
        Connected,
        Disconnected
    }

}
