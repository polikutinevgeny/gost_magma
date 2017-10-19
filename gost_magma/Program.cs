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
            Console.OutputEncoding = Encoding.UTF8;
            MagmaProvider magma = new MagmaProvider(0)
            {
                Key = "Hello there how are you doing?))"
            };
            var t = magma.CBCEncrypt("Lorem ipsum dolor sit amet. This is plaintext. I repeat: this is plaintext. Работает ли русский шрифт?", 0);
            foreach (var b in t.Encrypted)
            {
                Console.WriteLine(b);
            }
            Console.WriteLine();
            Console.WriteLine(magma.CBCDecrypt(t, 0));
            Console.ReadLine();
        }
    }
}
