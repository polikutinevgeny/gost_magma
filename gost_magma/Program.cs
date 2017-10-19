using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace gost_magma
{
    class Program
    {
        static void Main(string[] args)
        {
            MagmaProvider magma = new MagmaProvider
            {
                Key = "testtesttesttesttesttesttesttest"
            };
            magma.SeedSbox(0);
            Console.WriteLine(magma.CBC("test", 0).Encrypted);
            Console.ReadLine();
        }
    }
}
