using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SecureSocket
{



    public class SslClient
    {


        public int _countWriteQueue = 0;
        public int _countWrite = 0;

        public TcpClient tcp;
        public SslStream stream;
        public IPEndPoint ip;


        public int clientID; // unique ID for this connection
        public string userID; // email or username
        public bool IsAuth = false;



        // added for queueing messges to avoid the beginWrite error on SSL streams
        //ConcurrentQueue<byte[]> writePendingData = new ConcurrentQueue<byte[]>();

        private bool _pendingSend = false;
        private Queue _sendQueue = new Queue();
        
        const int BUFFERSIZE = 4096;
        private byte[] _readBuffer = null;





        // class for storing a reference to the stream
        // and some metadata about the client/username/status/etc
        public SslClient(TcpClient tcp)
        {
            this.tcp = tcp;
            this.userID = "foo@bar.com";
        }



        public SslStream GetStream()
        {
            return this.stream;
        }





        /// <summary>
        /// Send data to the server.
        /// </summary>
        public void Send(byte[] bData)
        {
            lock (this)
            {
                try
                {

                    // .NET 2.0 SSL Stream issues when sending multiple async packets
                    if (_pendingSend)
                    {
                        _sendQueue.Enqueue(bData);
                    }
                    else
                    {
                        _pendingSend = true;
                        try
                        {
                            stream.BeginWrite(bData, 0, bData.Length, new AsyncCallback(EndSend), null);
                        }
                        catch (Exception)
                        {
                            Disconnect();
                        }
                    }
                }
                catch (Exception)
                {

                }
            }
        }

        private void EndSend(IAsyncResult ar)
        {
            lock (this)
            {
                try
                {
                    stream.EndWrite(ar);
                    if (_sendQueue.Count > 0)
                    {
                        byte[] bData = (byte[])_sendQueue.Dequeue();
                        stream.BeginWrite(bData, 0, bData.Length, new AsyncCallback(EndSend), null);
                    }
                    else
                    {
                        _pendingSend = false;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception: " + e.Message);
                    Disconnect();
                }
            }
        }






        /// <summary>
        /// Read data from server.
        /// </summary>
        private void Receive()
        {
            stream.BeginRead(_readBuffer, 0, BUFFERSIZE, new AsyncCallback(EndReceive), null);
        }

        private void EndReceive(IAsyncResult ar)
        {
            try
            {
                int nBytes;
                nBytes = stream.EndRead(ar);
                if (nBytes > 0)
                {
                    Receive();
                }
                else
                {
                    Disconnect();
                }
            }
            catch (ObjectDisposedException)
            {
                //object already disposed, just exit
                return;
            }
            catch (IOException e)
            {
                Console.WriteLine("Socket Exception: " + e.Message);
                Disconnect();
            }
        }






        public void Disconnect()
        {
            lock (this)
            {
                _pendingSend = false;
                _sendQueue.Clear();
            }


            Console.WriteLine("This is where we need to disconnect the client");

        }








    }




}
