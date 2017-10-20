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
            MagmaProvider magma = new MagmaProvider()
            {
                Key = "Hello there how are you doing?))"
            };
            var t = magma.CFBEncrypt("Lorem ipsum dolor sit amet. This is plaintext. I repeat: this is plaintext. Работает ли русский шрифт?", new byte[8]);
            foreach (var b in t.Encrypted)
            {
                Console.Write((char)b);
            }
            Console.WriteLine();
            Console.WriteLine(magma.CFBDecrypt(t, new byte[8]));
            Console.ReadLine();
        }
    }
}
