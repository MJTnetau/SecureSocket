using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocket
{



    // this class describes the protocols used for messaging between client-server
    public class Proto
    {

        ////////////////////////////////////////////////////////////
        // Message structural stuff


        // This delimeter used to signify the end of a message
        // all messages must end with this delimeter. 
        // The decode/parse loop does not consider a message to be complete until it sees this.
        public const string delim = "[END]"; 

        // some dummy padding, used for padding out message size in testing
        // client strips this and discards it
        public const string padding = "[abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ]";







    }







}
