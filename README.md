# SecureSocket
C# secure sockets via TCP, with TLS 1.2


## Example server app
```
using SecureSocket;

Server consoleServer = new Server("certificatepath.pfx", "certificatepassword", allowInvalidCert);

// Handle the following events
consoleServer.OnClientConnectedEvent += HandleClientConnected;
consoleServer.OnClientDisconnectedEvent += HandleClientDisconnected;
consoleServer.OnTextReceivedEvent += HandleTextReceived;
consoleServer.OnStatusEvent += HandleStatus;

// Tell the server to start listening
consoleServer.StartListening(ip, port);

// Optional - Tell the server to send out a regular heartbeat
consoleServer.StartTicking(tickrate);
```


## Example client app
```
using SecureSocket;

Client consoleClient = new Client();

// Handle the following events
consoleClient.OnTextReceivedEvent += HandleTextReceived;
consoleClient.OnServerConnectedEvent += HandleServerConnected;
consoleClient.OnTickEvent += HandleTick;

// Tell the client to connect
consoleClient.CreateClient();
consoleClient.SetServerIPAddress(ip);
consoleClient.SetPortNumber(port);
consoleClient.Connect();
```