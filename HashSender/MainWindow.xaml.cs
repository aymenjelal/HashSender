using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;

namespace HashSender
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        UnicodeEncoding ByteConverter = new UnicodeEncoding();
        public static RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
        string publicKey = RSA.ToXmlString(false);
        string receiverPublicKey;

        public MainWindow()
        {
            InitializeComponent();
            receiverPublicKey = ExecuteServer(publicKey);
        }

        private void SendFile_Click(object sender, RoutedEventArgs e)

        {


            string lines;

            lines = File.ReadAllText(path.Text);
            Console.WriteLine("message read " + lines);

            byte[] plainText = ByteConverter.GetBytes(lines);
            var receiverRsa = new RSACryptoServiceProvider();
            receiverRsa.FromXmlString(receiverPublicKey);

            string signedMessage = SignData(lines, RSA.ExportParameters(true));

            string fullPath = @"C:\Users\Aymen\Desktop\exx1.txt";

            using (StreamWriter writer = new StreamWriter(fullPath,false))
            {
                writer.Write(signedMessage);
            }

        }

        private void BrowseFile_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();

            Nullable<bool> result = dlg.ShowDialog();

            if (result == true)
            {
                // Open document 
                string filename = dlg.FileName;
                path.Text = filename;
            }
        }

        public static string SignData(string message, RSAParameters privateKey)
        {
            //// The array to store the signed message in bytes
            byte[] signedBytes;
            using (var rsa = new RSACryptoServiceProvider())
            {
                //// Write the message to a byte array using UTF8 as the encoding.
                var encoder = new UTF8Encoding();
                byte[] originalData = encoder.GetBytes(message);

                try
                {
                    //// Import the private key used for signing the message
                    rsa.ImportParameters(privateKey);

                    //// Sign the data, using SHA512 as the hashing algorithm 
                    signedBytes = rsa.SignData(originalData, CryptoConfig.MapNameToOID("SHA512"));
                }
                catch (CryptographicException e)
                {
                    Console.WriteLine(e.Message);
                    return null;
                }
                finally
                {
                    //// Set the keycontainer to be cleared when rsa is garbage collected.
                    rsa.PersistKeyInCsp = false;
                }
            }
            //// Convert the a base64 string before returning
            return Convert.ToBase64String(signedBytes);
        }

        public static String ExecuteServer(string messageToClient)
        {
            // Establish the local endpoint  
            // for the socket. Dns.GetHostName 
            // returns the name of the host  
            // running the application. 
            IPHostEntry ipHost = Dns.GetHostEntry(Dns.GetHostName());
            IPAddress ipAddr = ipHost.AddressList[0];
            IPEndPoint localEndPoint = new IPEndPoint(ipAddr, 11111);

            // Creation TCP/IP Socket using  
            // Socket Class Costructor 
            Socket listener = new Socket(ipAddr.AddressFamily,
                         SocketType.Stream, ProtocolType.Tcp);

            try
            {

                // Using Bind() method we associate a 
                // network address to the Server Socket 
                // All client that will connect to this  
                // Server Socket must know this network 
                // Address 
                listener.Bind(localEndPoint);

                // Using Listen() method we create  
                // the Client list that will want 
                // to connect to Server 
                listener.Listen(10);

                while (true)
                {

                    Console.WriteLine("Waiting connection ... ");

                    // Suspend while waiting for 
                    // incoming connection Using  
                    // Accept() method the server  
                    // will accept connection of client 
                    Socket clientSocket = listener.Accept();

                    // Data buffer 
                    byte[] bytes = new Byte[1024];
                    string data = null;

                    while (true)
                    {

                        int numByte = clientSocket.Receive(bytes);

                        data += Encoding.ASCII.GetString(bytes,
                                                   0, numByte);

                        if (data.IndexOf("<EOF>") > -1)
                            break;
                    }

                    char[] charsToTrim = { ',', '.', ' ' };
                    string mesRec = data.Replace("<EOF>", "");
                    Console.WriteLine("Text received -> {0} ", mesRec);

                    byte[] message = Encoding.ASCII.GetBytes(messageToClient);

                    // Send a message to Client  
                    // using Send() method 
                    clientSocket.Send(message);

                    // Close client Socket using the 
                    // Close() method. After closing, 
                    // we can use the closed Socket  
                    // for a new Client Connection 
                    clientSocket.Shutdown(SocketShutdown.Both);
                    clientSocket.Close();
                    return mesRec;
                }
            }

            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
        }
    }
}
