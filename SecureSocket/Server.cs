using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;

namespace SecureSocket
{


    /// <summary>
    /// MJT Secure Socket - Server - Version 1.0
    /// Built with .NET Core 3.0
    /// Supports Asynchronous Socket Connections, with TLS 1.2 required
    /// Win 8, Win 10, Server 2012, Server 2016 support TLS 1.2 by default
    /// </summary>
    public class Server
    {

        // Server network settings
        private readonly X509Certificate2 _serverCertificate;

        private IPAddress _ip;
        private int _port;

        private TcpListener _listener;

        private bool sendImmediate = false; // enable noDelay on TCP





        // list of SslClient's (TcpClient + stream + metadata)
        private List<SslClient> clients;


        // Events
        public EventHandler<ClientConnectedEventArgs> OnClientConnectedEvent;
        public EventHandler<ClientDisconnectEventArgs> OnClientDisconnectedEvent;
        public EventHandler<TextReceivedEventArgs> OnTextReceivedEvent;
        public EventHandler<StatusEventArgs> OnStatusEvent;




        // Tick stuff
        private int _interval = 500; // if not specified by user in startTicking(16);
        //private bool _tickEnabled = true;
        private int _tickCount = 0;
        private static System.Timers.Timer _tickTimer;

        // stopwatches
        private Stopwatch _tickStopwatch = new Stopwatch();
        private string _tickLastStopwatch = "";






        #region Getters / Setters

        public bool KeepRunning { get; set; }

        public int GetClientCount
        {
            get { 
                return clients.Count; 
            }
        }

        public int GetInterval
        {
            get
            {
                return _interval;
            }
        }

        public int GetLastTick
        {
            get
            {
                return _tickCount;
            }
        }



        public string GetLastStopwatch
        {
            get
            {
                return _tickLastStopwatch;
            }
        }

        #endregion







        /// <summary>
        /// Constructor - Creates a Server with the specified security settings
        /// </summary>
        /// <param name="cert">The relative path to the certificate to be used</param>
        /// <param name="pass">The password used in the certificate</param>
        /// <param name="allowAllCertificates">If true, will allow invalid certificates to be used</param>
        public Server(string cert, string pass = null, bool allowAllCertificates = false)
        {
            // check for existence of certificate file
            if (string.IsNullOrEmpty(cert))
            {
                WriteLog("certificate: " + " no certificate path provided");
                throw new ArgumentNullException(nameof(cert));
            }

            if (string.IsNullOrEmpty(pass))
            {
                _serverCertificate = new X509Certificate2(File.ReadAllBytes(Path.GetFullPath(cert)));
                WriteLog("certificate: " + cert + " pass: none");
            }
            else
            {
                _serverCertificate = new X509Certificate2(File.ReadAllBytes(Path.GetFullPath(cert)), pass);
                WriteLog("certificate: " + cert + " pass: provided");
            }


            // create the client list
            // this is really just a list of TcpClient's
            clients = new List<SslClient>();
        }





        /// <summary>
        /// Start listening for connections - If not provided, default to IPAddress.Any. Port 10001
        /// </summary>
        /// <param name="ip">A specific IP address to listen on, or 'null' for default </param>
        /// <param name="port"></param>
        public async void StartListening(IPAddress ip = null, int port = 10001)
        {

            if (ip == null)
            {
                ip = IPAddress.Any;
            }

            if (port <= 0)
            {
                port = 10001;
            }

            _ip = ip;
            _port = port;

            _listener = new TcpListener(_ip, _port);

            try
            {
                
                _listener.Start();
                

                KeepRunning = true;

                /////////////////////////////////////////////
                // Server Listen Loop
                /////////////////////////////////////////////
                while (KeepRunning)
                {
                    var newClient = await _listener.AcceptTcpClientAsync();

                    if (sendImmediate)
                    {
                        newClient.NoDelay = true;
                    }


                    HandleClient(newClient);

                    // publisher side -- Create an event args, and send it
                    ClientConnectedEventArgs eaClientConnected;
                    eaClientConnected = new ClientConnectedEventArgs(newClient.Client.RemoteEndPoint.ToString(), newClient);
                    RaiseClientConnectedEvent(eaClientConnected);

                }
            }
            catch (InvalidOperationException e)
            {
                WriteLog("Invalid Operation exception during StartListening : " + e.ToString());
            }
            catch (SocketException e)
            {
                WriteLog("Socket exception during StartListening : " + e.ToString());
            }
            catch (Exception e)
            {
                WriteLog("General exception during StartListening : " + e.ToString());
            }

        }



        /// <summary>
        /// Stops listening for connections. Kicks all users. Clears client list
        /// </summary>
        public void StopServer()
        {
            try
            {
                if (_listener != null)
                {
                    _listener.Stop();
                }

                for (int i = 0; i < clients.Count; i++)
                {
                    SslClient c = clients[i];
                    KickUser(c, "Server stopping");
                }

            }
            catch (Exception e)
            {
                WriteLog(e.ToString());
            }

            clients.Clear();

        }





        /// <summary>
        /// Handles the clinet and converts it to a SSL stream. Authenticates with certificate, 
        /// welcomes the client, and then starts a loop to receive messages. It then passes these on to methods
        /// that decode and parse the messages
        /// </summary>
        private async void HandleClient(TcpClient client)
        {
            // make a new Receiver object to hold this users connection stuff
            SslClient c = new SslClient(client);
            c.stream = new SslStream(c.tcp.GetStream(), false);

            // convert the TcpClient to a SslStream
            SslStream sslStream = c.stream;


            /// Authenticate
            try
            {
                await sslStream.AuthenticateAsServerAsync(_serverCertificate, false, SslProtocols.Tls12, true);

                // only add client now after authenticate success
                clients.Add(c);

                WriteLog("User connected. SSL Authenticated");
            }
            catch (IOException e)
            {
                KickUser(c, "IO exception during Authenticate");
                WriteLog("IO exception during Authenticate : " + e.ToString());
            }
            catch (SocketException e)
            {
                KickUser(c, "Socket exception during Authenticate");
                WriteLog("Socket exception during Authenticate : " + e.ToString());
            }
            catch (Exception e)
            {
                KickUser(c, "Exception during Authenticate");
                WriteLog("Exception during Authenticate : " + e.ToString());
            }


            /// Welcome
            try
            {
                byte[] welcomeMessage = Encoding.UTF8.GetBytes("Welcome SSL Client" + Proto.delim);



                c.Send(welcomeMessage);

                ///c.WriteQueue(welcomeMessage);

                //await c.stream.WriteAsync(welcomeMessage, 0, welcomeMessage.Length);
                //await c.stream.FlushAsync();

                WriteLog("Sent Welcome message");
            }
            catch (IOException e)
            {
                KickUser(c, "IO exception during Welcome");
                WriteLog("IO exception during Welcome : " + e.ToString());
            }
            catch (SocketException e)
            {
                KickUser(c, "Socket exception during Welcome");
                WriteLog("Socket exception during Welcome : " + e.ToString());
            }
            catch (Exception e)
            {
                KickUser(c, "Exception during Welcome");
                WriteLog("Exception during Welcome : " + e.ToString());
            }


            /// Running
            try
            {
                ///////////////////////////////////////////////////////////
                // main server loop
                ///////////////////////////////////////////////////////////
                while (KeepRunning)
                {

                    // get decoded messages from the stream
                    string messageData = await DecodeMessage(c.stream);


                    // if empty, then quit
                    if (string.IsNullOrEmpty(messageData))
                    {
                        KickUser(c, "Client disconnected gracefully (Empty message received)");
                        break;
                    }


                    // decide what to do with the message
                    // is it !command, text, ping, etc
                    ParseMessage(c, messageData);

                }

            }
            catch (IOException e)
            {
                KickUser(c, "IO exception during Run");
                
                /// this is when the client disconnects forcefully. Like closing the app without disconnecting
                WriteLog("IO exception during Run : ||||" + e.Message + "||||" + e.ToString());
            }
            catch (SocketException e)
            {
                KickUser(c, "Socket exception during Run");
                WriteLog("Socket exception during Run : " + e.ToString());
            }
            catch (Exception e)
            {
                KickUser(c, "Exception during Run");
                WriteLog("Exception during Run : " + e.ToString());
            }

        }





        /////////////////////////////////////////////////////////////////////////
        // Process and Decode messages - Parse looking for Message [TYPE]
        /////////////////////////////////////////////////////////////////////////

        /// <summary>
        /// Decode the bytes from the start of the message to the [END] delimeter.
        /// </summary>
        private async Task<string> DecodeMessage(SslStream sslStream)
        {
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
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
        private void ParseMessage(SslClient r, string theMessage)
        {
            //WriteLog("inside parseMessage | " + r.userID + " | " + theMessage);

            // if its text, raise an event
            RaiseTextReceivedEvent(new TextReceivedEventArgs(r.userID, theMessage));
        }







        /////////////////////////////////////////////////////////////////////////
        // Send Messages to users
        /////////////////////////////////////////////////////////////////////////

        // send to all users
        public async Task SendToAll(string theMessage)
        {
            if (string.IsNullOrEmpty(theMessage))
            {
                return;
            }

            byte[] message = Encoding.UTF8.GetBytes(theMessage + Proto.delim);


            int broadcastSuccess = 0;

            WriteLog("Broadcasting to " + clients.Count + ": " + theMessage);


            SslClient c;


            for (int i = 0; i < clients.Count; i++)
            {

                //Receiver r = clients[i];
                c = clients[i];

                // if not null, and is connected
                if (c != null)
                {
                    if (c.tcp.Connected)
                    {
                        try
                        {
                            c.Send(message);
                                
                            ///c.WriteQueue(message);

                            //await c.stream.WriteAsync(message, 0, message.Length);
                            //await c.stream.FlushAsync();



                            broadcastSuccess++;
                        }
                        catch (IOException e)
                        {
                            // innocuous ssl error
                            if (e.InnerException != null && e.InnerException is ObjectDisposedException)
                            {
                                WriteLog("IO Exception: ssl stream error");
                            }
                            else
                            {
                                WriteLog("IO Exception : Unknown : " + e.Message);
                            }
                            KickUser(c, "IO exception during Broadcast");
                            WriteLog("IO exception during Broadcast : " + e.ToString());
                        }
                        catch (SocketException e)
                        {
                            KickUser(c, "Socket exception during Broadcast");
                            WriteLog("Socket exception during Broadcast : " + e.ToString());
                        }
                        catch (Exception e)
                        {
                            KickUser(c, "Exception during Broadcast");
                            WriteLog("Exception during Broadcast : " + e.ToString());
                        }

                    }
                }

            }

            WriteLog("Broadcasting success " + broadcastSuccess.ToString() + "/" + clients.Count);

        }



        // send to specific user
        public async void SendTo(SslClient c, string theMessage)
        {

            if (string.IsNullOrEmpty(theMessage))
            {
                return;
            }

            byte[] message = Encoding.UTF8.GetBytes(theMessage);

            // if not null, and is connected
            if (c != null)
            {
                if (c.tcp.Connected)
                {
                    try
                    {

                        c.Send(message);

                    }
                    catch (IOException e)
                    {
                        // innocuous ssl error
                        if (e.InnerException != null && e.InnerException is ObjectDisposedException)
                        {
                            WriteLog("IO Exception: ssl stream error");
                        }
                        else
                        {
                            WriteLog("IO Exception : Unknown : " + e.Message);
                        }
                        KickUser(c, "IO exception during Send");
                        WriteLog("IO exception during Send : " + e.ToString());
                    }
                    catch (SocketException e)
                    {
                        KickUser(c, "Socket exception during Send");
                        WriteLog("Socket exception during Send : " + e.ToString());
                    }
                    catch (Exception e)
                    {
                        KickUser(c, "Exception during Send");
                        WriteLog("Exception during Send : " + e.ToString());
                    }

                }
            }

        }






        /////////////////////////////////////////////////////////////////////////
        // Kick user
        /////////////////////////////////////////////////////////////////////////

        private void KickUser(SslClient c, string reason)
        {

            if (c != null)
            {
                try
                {
                    // publisher side -- Create an event args, and send it
                    ClientDisconnectEventArgs eaClientDisconnect;
                    eaClientDisconnect = new ClientDisconnectEventArgs(c.tcp.Client.RemoteEndPoint.ToString(), c.tcp);
                    RaiseClientDisconnectedEvent(eaClientDisconnect);

                    // drop the tcp
                    c.tcp.Close();

                    // remove the receiver from list
                    RemoveClient(c);

                    WriteLog("Kicked Client : " + reason);
                }

                catch (ObjectDisposedException e)
                {
                    WriteLog("Object Disposed exception during Kick: SSL stream error" + e.ToString());
                }
                catch (IOException e)
                {
                    // innocuous ssl error
                    if (e.InnerException != null && e.InnerException is ObjectDisposedException)
                    {
                        // innocuous ssl error - this is expected to happen
                        WriteLog("IO Exception during Kick: SSL stream error" + e.ToString());
                    }
                    else
                    {
                        WriteLog("IO Exception during Kick : Unknown : " + e.Message);
                    }

                    WriteLog("IO exception during Kick : " + e.ToString());
                }
                catch (SocketException e)
                {
                    WriteLog("Socket exception during Kick : " + e.ToString());
                }
                catch (Exception e)
                {
                    WriteLog("Problem trying to Kick user. Generic Exception: " + e.ToString());
                }

            }
            else
            {
                WriteLog("Problem trying to Kick user. User's Socket was null");
            }



        }


        // only removes the receiver from the list
        private void RemoveClient(SslClient c)
        {
            if (clients.Contains(c))
            {
                clients.Remove(c);
            }
            else
            {
                WriteLog("Could not remove Client - Count now (still) at " + clients.Count.ToString());
            }

            // TODO
            // issue a client connected event args

        }






        /////////////////////////////////////////////////////////////////////////
        // This is getting called at 60Hz, or 10Hz, or whatever tickrate is
        /////////////////////////////////////////////////////////////////////////
        private async Task SendTicks(string s)
        {
            byte[] message = Encoding.UTF8.GetBytes(s);


            // benchmarking tick loop
            _tickStopwatch.Start();


            // Loop over clients, and send Ticks
            for (int i = 0; i < clients.Count; i++)
            {
                SslClient c = clients[i];

                    if (c != null)
                    {
                        if (c.tcp.Connected)
                        {

                            // TODO if it is authenticated

                            if (c.stream.IsAuthenticated)
                            {
                                //WriteLog("isAuthenticated");
                            }
                            else
                            {
                                WriteLog("NOT isAuthenticated");
                            }





                            // TODO if can begin write ?
                            if (c.stream.CanWrite)
                            {
                                //WriteLog("stream can CanWrite");
                            }
                            else
                            {
                                WriteLog("stream was not CanWrite");
                            }



                            try
                            {
                                /////////////////////////////////////////////////////////////////
                                /// The actual write

                                c.Send(message);

                                /////////////////////////////////////////////////////////////////
                            }
                            catch (ObjectDisposedException e)
                            {
                                WriteLog("Object Disposed exception during Tick : " + e.ToString());
                            }
                            catch (NotSupportedException e)
                            {
                                WriteLog("Not Supported exception during Tick : " + e.ToString());
                            }
                            catch (InvalidOperationException e)
                            {
                                WriteLog("Invalid Operation exception during Tick : " + e.ToString());
                            }
                            catch (IOException e)
                            {
                                WriteLog("IO exception during Tick : " + e.ToString());
                            }
                            catch (SocketException e)
                            {
                                WriteLog("Socket exception during Tick : " + e.ToString());
                            }
                            catch (Exception e)
                            {
                                //Exception thrown: 'System.InvalidOperationException' in System.dll
                                WriteLog("General Exception during Tick : " + e.ToString());
                            }
                        }
                    }
            }


            _tickLastStopwatch = _tickStopwatch.Elapsed.ToString();
            _tickStopwatch.Restart();

        }



    



        /// <summary>
        /// Starts a server ticker, sending out [TICK]12345 at the given rate. If not specified, will run at 500ms
        /// </summary>
        /// <param name="tickrate"></param>
        public void StartTicking(int tickrate)
        {
            _interval = tickrate;

            // create tick timer
            _tickTimer = new System.Timers.Timer(_interval);
            _tickTimer.Elapsed += OnTickTimerEvent;
            _tickTimer.Start();
        }


        private async void OnTickTimerEvent(object sender, ElapsedEventArgs e)
        {
            _tickCount++;

            await SendTicks("[TICK]" + _tickCount.ToString() + Proto.delim);
        }







        //////////////////////////////////////////////////////////////////
        // Events
        // You have to subscribe to the events in your app
        //////////////////////////////////////////////////////////////////
        #region events

        // any derived classes can override invocation if they need to
        protected virtual void RaiseClientConnectedEvent(ClientConnectedEventArgs e)
        {
            // temp copy
            EventHandler<ClientConnectedEventArgs> handler = OnClientConnectedEvent;

            if (handler != null)
            {
                handler(this, e);
            }
        }


        protected virtual void RaiseClientDisconnectedEvent(ClientDisconnectEventArgs e)
        {
            // temp copy
            EventHandler<ClientDisconnectEventArgs> handler = OnClientDisconnectedEvent;

            if (handler != null)
            {
                handler(this, e);
            }
        }


        protected virtual void RaiseTextReceivedEvent(TextReceivedEventArgs trea)
        {
            // temp copy
            EventHandler<TextReceivedEventArgs> handler = OnTextReceivedEvent;

            if (handler != null)
            {
                handler(this, trea);
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

        #endregion









        //////////////////////////////////////////////////////////////////
        // Some output functions for debugging
        //////////////////////////////////////////////////////////////////
        public void GetClientStats()
        {
            // Loop over clients, and send Ticks
            for (int i = 0; i < clients.Count; i++)
            {
                SslClient c = clients[i];
                Console.WriteLine("Client[" + i + "] counters _countWrite:" + c._countWrite + "    _countWriteQueue:" + c._countWriteQueue);
            }
        }



        //////////////////////////////////////////////////////////////////
        // Logs
        private void WriteLog(string message)
        {
            Console.WriteLine(message);
        }











    }


}
