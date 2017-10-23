using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace gost_magma
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;
            Console.Write("Введите имя входного файла: ");
//            byte[] input = File.ReadAllBytes(Console.ReadLine());
            string input = Console.ReadLine();
            Console.Write("Введите имя выходного файла: ");
            string output = Console.ReadLine();
            Console.Write("Введите ключ: ");
            string key = Console.ReadLine();
            Console.Write("Выберите режим: 0 - зашифровать, 1 - расшифровать: ");
            int mode = Convert.ToInt32(Console.ReadLine());
            Console.Write("Выберите режим шифрования: CBC, CFB, OFB: ");
            string encMode = Console.ReadLine();
            MagmaProvider magma = new MagmaProvider()
            {
                Key = key
            };
            if (mode == 0)
            {
                byte[] inBytes = File.ReadAllBytes(input);
                Result outBytes;
                switch (encMode)
                {
                    case "CBC":
                        outBytes = magma.CBCEncrypt(inBytes, 66467);
                        break;
                    case "CFB":
                        outBytes = magma.CFBEncrypt(inBytes, 66467);
                        break;
                    case "OFB":
                        outBytes = magma.OFBEncrypt(inBytes, 66467);
                        break;
                    default:
                        return;
                }
                using (var fs = new FileStream(output, FileMode.Create, FileAccess.Write))
                {
                    fs.Write(BitConverter.GetBytes(outBytes.Length), 0, 4);
                    fs.Write(outBytes.Encrypted, 0, outBytes.Encrypted.Length);
                }
            }
            if (mode == 1)
            {
                byte[] inBytes = File.ReadAllBytes(input);
                Int32 length = BitConverter.ToInt32(inBytes, 0);
                Result inp = new Result(inBytes.Skip(4).ToArray(), length);
                byte[] outBytes;
                switch (encMode)
                {
                    case "CBC":
                        outBytes = magma.CBCDecrypt(inp, 66467);
                        break;
                    case "CFB":
                        outBytes = magma.CFBDecrypt(inp, 66467);
                        break;
                    case "OFB":
                        outBytes = magma.OFBDecrypt(inp, 66467);
                        break;
                    default:
                        return;
                }
                File.WriteAllBytes(output, outBytes);
            }
//            var t = magma.OFBEncrypt("Lorem ipsum dolor sit amet. This is plaintext. I repeat: this is plaintext. Работает ли русский шрифт?", 0);
//            foreach (var b in t.Encrypted)
//            {
//                Console.Write((char)b);
//            }
//            Console.WriteLine();
//            Console.WriteLine(magma.OFBDecrypt(t, 0));
//            Console.ReadLine();
        }
    }
}
