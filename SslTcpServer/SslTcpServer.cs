using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SslTcpServer
{
    class SslTcpServer
    {
        static X509Certificate serverCertificate = null;
        static void RunServer(int servicePort, string certificatePath, string certificatePwd)
        {
            serverCertificate = new X509Certificate2(certificatePath, certificatePwd);
            TcpListener listener = new TcpListener(IPAddress.Any, servicePort);
            listener.Start();
            while (true)
            {
                try
                {
                    Console.WriteLine("Waiting for a client to connect...");
                    TcpClient client = listener.AcceptTcpClient();
                    ProcessClient(client);
                }
                catch { }
            }
        }
        static void RunServer(int servicePort)
        {
            TcpListener listener = new TcpListener(IPAddress.Any, servicePort);
            listener.Start();
            while (true)
            {
                try
                {
                    Console.WriteLine("Waiting for a client to connect...");
                    TcpClient client = listener.AcceptTcpClient();
                    ProcessClient(client);
                }
                catch { }
            }
        }
        static void ProcessClient(TcpClient client)
        {
            SslStream sslStream = new SslStream(client.GetStream(), false);
            try
            {
                sslStream.AuthenticateAsServer(serverCertificate, false, SslProtocols.Tls, true);
                DisplaySecurityLevel(sslStream);
                DisplaySecurityServices(sslStream);
                DisplayCertificateInformation(sslStream);
                DisplayStreamProperties(sslStream);

                sslStream.ReadTimeout = 5000;
                sslStream.WriteTimeout = 5000;
                byte[] message = Encoding.UTF8.GetBytes("Hello from the server.");
                Console.WriteLine("Sending hello message.");
                sslStream.Write(message);
                Console.WriteLine("Waiting for client message...");

                while (true)
                {
                    string messageData = ReadMessage(sslStream);
                    Console.WriteLine("Received: {0}", messageData);
                    if (messageData.ToUpper() == "EXIT")
                        break;
                }
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                sslStream.Close();
                client.Close();
                return;
            }
            finally
            {
                sslStream.Close();
                client.Close();
            }
        }
        static string ReadMessage(SslStream sslStream)
        {
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                bytes = sslStream.Read(buffer, 0, buffer.Length);
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);
                if (messageData.ToString().IndexOf("") != -1)
                {
                    break;
                }
            }
            while (bytes != 0);

            return messageData.ToString();
        }
        static void DisplaySecurityLevel(SslStream stream)
        {
            Console.WriteLine("Cipher: {0} strength {1}", stream.CipherAlgorithm, stream.CipherStrength);
            Console.WriteLine("Hash: {0} strength {1}", stream.HashAlgorithm, stream.HashStrength);
            Console.WriteLine("Key exchange: {0} strength {1}", stream.KeyExchangeAlgorithm, stream.KeyExchangeStrength);
            Console.WriteLine("Protocol: {0}", stream.SslProtocol);
        }
        static void DisplaySecurityServices(SslStream stream)
        {
            Console.WriteLine("Is authenticated: {0} as server? {1}", stream.IsAuthenticated, stream.IsServer);
            Console.WriteLine("IsSigned: {0}", stream.IsSigned);
            Console.WriteLine("Is Encrypted: {0}", stream.IsEncrypted);
        }
        static void DisplayStreamProperties(SslStream stream)
        {
            Console.WriteLine("Can read: {0}, write {1}", stream.CanRead, stream.CanWrite);
            Console.WriteLine("Can timeout: {0}", stream.CanTimeout);
        }
        static void DisplayCertificateInformation(SslStream stream)
        {
            Console.WriteLine("Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus);

            X509Certificate localCertificate = stream.LocalCertificate;
            if (stream.LocalCertificate != null)
            {
                Console.WriteLine("Local cert was issued to {0} and is valid from {1} until {2}.",
                localCertificate.Subject,
                    localCertificate.GetEffectiveDateString(),
                    localCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Local certificate is null.");
            }
            X509Certificate remoteCertificate = stream.RemoteCertificate;
            if (stream.RemoteCertificate != null)
            {
                Console.WriteLine("Remote cert was issued to {0} and is valid from {1} until {2}.",
                    remoteCertificate.Subject,
                    remoteCertificate.GetEffectiveDateString(),
                    remoteCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Remote certificate is null.");
            }
        }

        public static void Test1()
        {
            //如果证书是自制的，那么请先将证书导入到“受信任的根证书颁发机构”中
            int servicePort = 12345;
            string certificatePath = @"C:\Users\kinbor\Documents\Test.pfx";
            string certificatePwd = "123456789";
            RunServer(servicePort, certificatePath, certificatePwd);
            Console.ReadLine();
        }
        public static void Test2()
        {
            try
            {
                int servicePort = 12345;
                string certificateName = "TestServer";

                X509Store store = new X509Store(StoreName.Root);
                store.Open(OpenFlags.ReadWrite);
                // 检索证书 
                X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectName, certificateName, false); // vaildOnly = true时搜索无结果。
                if (certs.Count == 0) return;

                serverCertificate = certs[0];
                RunServer(servicePort);
                store.Close(); // 关闭存储区。
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            Console.ReadLine();
        }
    }
}
