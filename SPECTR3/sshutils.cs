using Renci.SshNet.Common;
using Renci.SshNet;
using System;

namespace SPECTR3
{
    internal class SPECTR3SSH
    {
        public SshClient sshclient;
        public ForwardedPortRemote fwdport;

        public void StartSshReverseTunnel(String sshhost,int sshport, String sshuser, String sshpass, uint dstport)
        {
            ConnectionInfo ConnNfo = new ConnectionInfo(sshhost, sshport, sshuser, new AuthenticationMethod[] { new PasswordAuthenticationMethod(sshuser, sshpass) });
            sshclient = new SshClient(ConnNfo);
            sshclient.KeepAliveInterval = new TimeSpan(0, 0, 30);
            sshclient.ConnectionInfo.Timeout = new TimeSpan(0, 0, 20);
            try
            {
                sshclient.Connect();
            }
            catch (Exception ex)
            {
                Console.WriteLine("    + Cannot connect to SSH server, " + ex.Message, "Error");
                return;
            }

            fwdport = new ForwardedPortRemote(dstport, "127.0.0.1", dstport);
            if (sshclient.IsConnected)
            {
                sshclient.AddForwardedPort(fwdport);
                fwdport.Exception += delegate (object sender, ExceptionEventArgs e)
                {
                    Console.WriteLine("    + Error forwarding port: " + e.Exception.ToString());
                };
                fwdport.Start();
                Console.WriteLine("    + SSH Tunnel successfully connected to " + sshhost + ":" + sshport);
            }
            Console.WriteLine("  - Press any key to disconnect ssh tunnel ...  ");
            Console.ReadLine();
            CloseRemoteSSHTune();
        }

        public void CloseRemoteSSHTune()
        {
            fwdport.Stop();
            sshclient.Disconnect();
            Console.WriteLine("    + SSH Tunnel disconnected");
        }

    }
}
