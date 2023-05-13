using Renci.SshNet.Common;
using Renci.SshNet;
using System;
using System.Threading.Tasks;


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
            sshClient.Connect();

            fwdPort = new ForwardedPortRemote(dstPort, "127.0.0.1", dstPort);
            if (sshClient.IsConnected)
            {
                sshClient.AddForwardedPort(fwdPort);
                fwdPort.Exception += delegate (object sender, ExceptionEventArgs e)
                {
                    Console.WriteLine("    + Error forwarding port: {0}", e.Exception);
                };
                fwdPort.Start();
                Console.WriteLine("    + SSH tunnel successfully connected to {0}:{1}", sshHost, sshPort);
            }
        }

        public async Task CloseRemoteSSHTunnelAsync()
        {
            await Task.Run(() =>
            {
                fwdPort.Stop();
                sshClient.Disconnect();
                Console.WriteLine("    + SSH tunnel disconnected.");
            });
        }

        public void CloseRemoteSSHTunnel()
        {
            fwdPort.Stop();
            sshClient.Disconnect();
            Console.WriteLine("    + SSH tunnel disconnected.");
        }
    }
}
