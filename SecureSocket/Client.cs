using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SecureSocket
{


    /// <summary>
    /// MJT Secure Socket - Client - Version 1.0
    /// Built with .NET Core 3.0
    /// Supports Asynchronous Socket Connections, with TLS 1.2 required
    /// </summary>
    public class Client
    {


        public bool KeepRunning { get; set; }


        private bool _connecting = false; // currently trying to connect?
        private bool _connected = false; // currently connected?

        private bool _retryConnect = true;
        private int _retryMax = 0; // 0 forever
        private int _retryAtempts = 0;
        private int _retryDelay = 3000; // ms
        private int _retryDelayVariance = 1000; // so they dont all connect at same time



        private IPAddress serverIP;
        private int serverPort;
        TcpClient aClient;


        private bool sendImmediate = true;

        private Stream stream;
        private SslStream sslStream;
        private string hostname = "mjt.net.au";



        public EventHandler<TextReceivedEventArgs> OnTextReceivedEvent;
        public EventHandler<ServerConnectedEventArgs> OnServerConnectedEvent;
        public EventHandler<StatusEventArgs> OnStatusEvent;
        public EventHandler<TickEventArgs> OnTickEvent;






        // Constructor
        public Client()
        {
            aClient = null;
            serverPort = -1;
            serverIP = null;
        }



        public IPAddress ServerIPAddress
        {
            get
            {
                return serverIP;
            }
        }

        public int ServerPort
        {
            get
            {
                return serverPort;
            }
        }

        public bool SetServerIPAddress(string _IPAddressServer)
        {

            IPAddress ipaddr = null;

            if (!IPAddress.TryParse(_IPAddressServer, out ipaddr))
            {
                Console.WriteLine("Invalid Server IP Address supplied");
                return false;
            }

            serverIP = ipaddr;
            return true;

        }

        public bool SetPortNumber(string _ServerPort)
        {
            int portNumber = 0;

            if (!int.TryParse(_ServerPort.Trim(), out portNumber))
            {
                Console.WriteLine("Invalid Server Port supplied");
                return false;
            }

            if (portNumber <= 0 || portNumber > 65535)
            {
                Console.WriteLine("Invalid Server Port. Must be 0 to 65535");
                return false;
            }

            serverPort = portNumber;
            return true;

        }





        // Just creates an instance of the TCP Client
        public async Task CreateClient()
        {

            // make client
            if (aClient == null)
            {
                Console.WriteLine("TcpClient was null");
                aClient = new TcpClient();

                if (sendImmediate)
                {
                    aClient.NoDelay = true;
                }

                Console.WriteLine("Created new TcpClient");
            }
            else
            {
                Console.WriteLine("TcpClient already existed");
                aClient = new TcpClient();

                if (sendImmediate)
                {
                    aClient.NoDelay = true;
                }

                Console.WriteLine("Created fresh TcpClient");
            }
            //

        }



        public async Task Connect()
        {


            // if not created
            CreateClient();



            if (_connecting)
            {
                Console.WriteLine("Connection attempt already in progress");
            }
            else
            {

                _retryAtempts++;

                // connect async
                try
                {
                    _connecting = true;

                    Console.WriteLine("Connecting....");
                    await aClient.ConnectAsync(serverIP, serverPort);
                    RaiseTextReceivedEvent(new TextReceivedEventArgs(aClient.Client.RemoteEndPoint.ToString(), "Connected to the server"));

                    Console.WriteLine("Convert to SSL");
                    stream = aClient.GetStream();

                    sslStream = new SslStream(stream, false, new RemoteCertificateValidationCallback(ValidateServerCertificate));
                    await sslStream.AuthenticateAsClientAsync(hostname);

                    RaiseServerConnectedEvent(new ServerConnectedEventArgs(sslStream));

                    _connecting = false;
                    _connected = true;
                    _retryAtempts = 0;
               

                    // Actually start running the loop to send/receive
                    Run();

                }
                catch (SocketException e)
                {
                    Close();
                    Console.WriteLine("Error connecting to server: " + e.ErrorCode + " " +e.Message);
                    RetryConnecting();

                }
                catch (Exception e)
                {
                    Close();
                    Console.WriteLine("General Error connecting to server: " + e.Message);
                    RetryConnecting();
                }

            }



        }









        private async Task RetryConnecting()
        {
            if (_connecting)
            {
                Console.WriteLine("Can't Retry. Connection attempt already in progress");
            }
            else
            {
                Console.WriteLine("Retrying connection");

                // retry connecting?
                if (_connected == false)
                {
                    if (_retryConnect)
                    {
                        if (_retryAtempts <= _retryMax || _retryMax == 0)
                        {
                            Console.WriteLine("Waiting..");
                            await Task.Delay(_retryDelay + Utils.RandInt(0, _retryDelayVariance));
                            Console.WriteLine("Retry attempt #" + _retryAtempts.ToString());
                            Connect();
                        }
                        else
                        {
                            Console.WriteLine("Tried reconneting maximum number of times");
                        }

                    }
                }

            }


        }







        /// <summary>
        /// This is the running loop. Keeps looking for new messages to parse
        /// </summary>
        /// <returns></returns>
        private async Task Run()
        { 

            // running
            try
            {

                KeepRunning = true;

                while (KeepRunning)
                {

                    // If there is a message to decode from Bytes
                    string messageData = await DecodeMessage(sslStream);

                    if (string.IsNullOrEmpty(messageData))
                    {
                        WriteLog("Client disconnected gracefully (Empty message received)");
                        Close();
                        break;
                    }

                    // handle it with the message parser
                    ParseMessage(messageData);

                }

            }
            catch (IOException e)
            {
                Close();
                //WriteLog("IO exception during Run : " + e.ToString());
                WriteLog("IO exception during Run : " + e.Message);
                RetryConnecting();
            }
            catch (SocketException e)
            {
                Close();
                WriteLog("Socket exception during Run : " + e.ErrorCode + " " + e.Message);
                RetryConnecting();
            }
            catch (Exception e)
            {
                Close();
                WriteLog("General Exception during Run : " + e.Message);
                RetryConnecting();
            }



        }





        #region decoding/parsing messages


        // Read the message sent by the client. The client signals the end of the message using the "[END]" marker.
        private async Task<string> DecodeMessage(SslStream sslStream)
        {
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;

            // keep looping, and reading from the buffer until it finds a [END] of message
            do
            {
                // Read the client's test message.
                bytes = await sslStream.ReadAsync(buffer, 0, buffer.Length);

                // Use Decoder class to convert from bytes to UTF8 in case a character spans two buffers.
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);

                messageData.Append(chars);

                // Check for [END] designated delimeter or an empty message.
                // if (messageData.ToString().IndexOf([END]) != -1)    // same as this
                if (messageData.ToString().IndexOf(Proto.delim) != -1)
                {
                    break;
                }
            }
            while (bytes != 0);

            return messageData.ToString();
        }





        /// <summary>
        /// Parse the message looking for [MSG TYPE], and hand off or respond accordingly
        /// </summary>
        private void ParseMessage(string theMessage)
        {
            //Console.WriteLine("Parsing:" + theMessage);

            // chop of any delimeter endings
            theMessage = theMessage.Replace(Proto.delim, "");

            // chop off the padding
            theMessage = theMessage.Replace(Proto.padding, "");


            if (theMessage.StartsWith("[TICK]"))
            {
                string theNewMessage = theMessage.Replace("[TICK]", "");
                RaiseTickEvent(new TickEventArgs(theNewMessage)); // this event gets sent subscribed to by whoever needs this data (eg a client app)
            }
            else
            {
                //WriteLog("Parse - Not a tick | " + "Server" + " | " + theMessage);
                // if its text, raise an event
                RaiseTextReceivedEvent(new TextReceivedEventArgs("Server", theMessage));
            }

        }


        #endregion





        // currently using 
        // await sslStream.WriteAsync
        // eg not a write queue
        public async Task SendToServer(string strInputUser)
        {

            if (string.IsNullOrEmpty(strInputUser))
            {
                Console.WriteLine("Empty string supplied");
                return;
            }


            if (aClient != null)
            {
                if (aClient.Connected)
                {


                    try
                    {

                        byte[] message = Encoding.UTF8.GetBytes(strInputUser + Proto.delim);
                        await sslStream.WriteAsync(message, 0, message.Length);
                        await sslStream.FlushAsync();
                        Console.WriteLine("SentAsync: " + strInputUser);

                    }
                    catch (IOException e)
                    {
                        if (e.InnerException != null && e.InnerException is ObjectDisposedException)
                        {
                            Console.WriteLine("IO Exception: innocuous ssl stream error :" + e.Message);
                        }
                        else
                        {
                            Console.WriteLine("IO Exception : Unknown : " + e.Message);
                        }

                        Close();
                        RetryConnecting();

                    }


                }
            }
        }















        public void Close()
        {

            _connecting = false;
            _connected = false;

            if (aClient != null)
            {
                if (aClient.Connected)
                {
                    aClient.Close();
                    //_connected = false;
                    Console.WriteLine("TCP Client is now closed");
                }
                else
                {
                    aClient.Close();
                    Console.WriteLine("TCP Client is re-closed");
                }
            }
            else
            {
                //_connected = false;
                Console.WriteLine("TCP Client is null");
            }

        }




        #region Logging


        //TODO add 2nd param of time
        // consuming event can decide to display it or not
        private void WriteLog(string s)
        {
            string messageDebug = DateTime.Now + " | " + s;

            Console.WriteLine(messageDebug);


        }


        // IO exception during AuthenticateAsServerAsync : System.IO.IOException: 
        //The process cannot access the file 'D:\^programming\_MJT\Net\Server\AsyncSecureSocket\Examples\FormServer\FormServer\bin\Debug\error.log' 
        //because it is being used by another process.
        async void AppendTextFile(string f, string s)
        {

            try
            {
                // using  flushes AND CLOSES the stream and calls IDisposable.Dispose on the stream object.
                using (StreamWriter writer = new StreamWriter(f, true))
                {
                    await writer.WriteAsync(s);
                    //Console.WriteLine("File write complete");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("File write failed " + e.ToString());
            }



        }

        #endregion











        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true;
            }

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            // return false;

            Console.WriteLine("Forcing ValidateServerCertificate to return true");
            // Force ssl certificates as correct by returning true
            return true;
        }





        #region Events

        protected virtual void RaiseTextReceivedEvent(TextReceivedEventArgs trea)
        {
            //RaiseTextReceivedEvent?.Invoke(this, trea);
            // temp copy
            EventHandler<TextReceivedEventArgs> handler = OnTextReceivedEvent;

            if (handler != null)
            {
                handler(this, trea);
            }

        }

        protected virtual void RaiseServerConnectedEvent(ServerConnectedEventArgs scea)
        {
            //RaiseServerConnectedEvent?.Invoke(this, scea);
            // temp copy
            EventHandler<ServerConnectedEventArgs> handler = OnServerConnectedEvent;

            if (handler != null)
            {
                handler(this, scea);
            }

        }

        protected virtual void RaiseStatusEvent(StatusEventArgs sea)
        {
            // temp copy
            EventHandler<StatusEventArgs> handler = OnStatusEvent;

            if (handler != null)
            {
                handler(this, sea);
            }


        }

        protected virtual void RaiseTickEvent(TickEventArgs tea)
        {
            // temp copy
            EventHandler<TickEventArgs> handler = OnTickEvent;

            if (handler != null)
            {
                handler(this, tea);
            }


        }

        #endregion




    }








}
