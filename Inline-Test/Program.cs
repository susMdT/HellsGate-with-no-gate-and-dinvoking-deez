using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Inline_Test
{
    public class Program
    {
        public static void Main(string[] args)
        {
            string argsString = "";
            foreach (var item in args)
            {
                argsString += item + " ";
            }
            Console.WriteLine("Okay, {0}", argsString);
        }
    }
}
