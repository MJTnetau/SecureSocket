using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocket
{
    public class Utils
    {


        /// <summary>
        /// Returns an Int inclusive. eg RandInt(1, 10) = 1, 3, 10
        /// </summary>
        public static int RandInt(int min, int max)
        {
            Random random = new Random();
            return random.Next(min, max+1);
        }

        /// <summary>
        /// Returns a double 0 to 0.99
        /// </summary>
        public static double RandDouble()
        {
            Random random = new Random();
            return random.NextDouble();
        }




    }
}
