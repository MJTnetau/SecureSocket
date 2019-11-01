using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SecureSocket
{

    /// <summary>
    /// Contains all of the EventArgs types of classes
    /// These event tpes are subscribed to by the Publiser Subscriber model
    /// EventArgs are like objects with the data associated with the event type
    /// 
    /// https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/events/how-to-publish-events-that-conform-to-net-framework-guidelines
    /// 
    /// </summary>




    // when a client has connected
    public class ClientConnectedEventArgs : EventArgs
    {
        public string NewClient { get; set; }
        public TcpClient NewTcpClient { get; set; }

        public ClientConnectedEventArgs(string _newClient, TcpClient _newTcpClient)
        {
            NewClient = _newClient;
            NewTcpClient = _newTcpClient;
        }

    }

    // when a client has disconnects
    public class ClientDisconnectEventArgs : EventArgs
    {
        public string NewClient { get; set; }
        public TcpClient NewTcpClient { get; set; }

        public ClientDisconnectEventArgs(string _newClient, TcpClient _newTcpClient)
        {
            NewClient = _newClient;
            NewTcpClient = _newTcpClient;
        }

    }

    // the server we connected to
    public class ServerConnectedEventArgs : EventArgs
    {
        //public string NewClient { get; set; }
        public SslStream NewSslStream { get; set; }

        //public ServerConnectedEventArgs(string _newClient, SslStream _newSslStream)
        public ServerConnectedEventArgs(SslStream _newSslStream)
        {
            //NewClient = _newClient;
            NewSslStream = _newSslStream;
        }

    }



    public class TextReceivedEventArgs : EventArgs
    {
        public string ClientWhoSentText { get; set; }
        public string TextReceived { get; set; }

        public TextReceivedEventArgs(string _clientWhoSentText, string _textReceived)
        {
            ClientWhoSentText = _clientWhoSentText;
            TextReceived = _textReceived;

        }

    }




    public class StatusEventArgs : EventArgs
    {
        public string StatusText { get; set; }

        public StatusEventArgs(string _statusText)
        {
            StatusText = _statusText;

        }

    }


    public class TickEventArgs : EventArgs
    {
        public string TickText { get; set; }

        public TickEventArgs(string _tick)
        {
            TickText = _tick;

        }

    }




}



