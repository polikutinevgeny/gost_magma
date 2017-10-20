using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Schema;

namespace gost_magma
{
    class MagmaProvider
    {
        private string _key;
        private UInt32[] _roundkeys;

        /// <summary>
        /// id-tc26-gost-28147-param-Z
        /// </summary>
        private readonly UInt32[,] _sbox = new UInt32[8, 16]
        {
            {0x0C, 0x04, 0x06, 0x02, 0x0A, 0x05, 0x0B, 0x09, 0x0E, 0x08, 0x0D, 0x07, 0x00, 0x03, 0x0F, 0x01},
            {0x06, 0x08, 0x02, 0x03, 0x09, 0x0A, 0x05, 0x0C, 0x01, 0x0E, 0x04, 0x07, 0x0B, 0x0D, 0x00, 0x0F},
            {0x0B, 0x03, 0x05, 0x08, 0x02, 0x0F, 0x0A, 0x0D, 0x0E, 0x01, 0x07, 0x04, 0x0C, 0x09, 0x06, 0x00},
            {0x0C, 0x08, 0x02, 0x01, 0x0D, 0x04, 0x0F, 0x06, 0x07, 0x00, 0x0A, 0x05, 0x03, 0x0E, 0x09, 0x0B},
            {0x07, 0x0F, 0x05, 0x0A, 0x08, 0x01, 0x06, 0x0D, 0x00, 0x09, 0x03, 0x0E, 0x0B, 0x04, 0x02, 0x0C},
            {0x05, 0x0D, 0x0F, 0x06, 0x09, 0x02, 0x0C, 0x0A, 0x0B, 0x07, 0x08, 0x01, 0x04, 0x03, 0x0E, 0x00},
            {0x08, 0x0E, 0x02, 0x05, 0x06, 0x09, 0x01, 0x0C, 0x0F, 0x04, 0x0B, 0x00, 0x0D, 0x0A, 0x03, 0x07},
            {0x01, 0x07, 0x0E, 0x0D, 0x00, 0x05, 0x08, 0x03, 0x04, 0x0F, 0x0A, 0x06, 0x09, 0x0C, 0x0B, 0x02}
        };

        public string Key
        {
            get => _key;
            set
            {
                if (Encoding.UTF8.GetBytes(value).Length == 32)
                {
                    _key = value;
                    _roundkeys = GetRoundKeys(Encoding.UTF8.GetBytes(value));
                }
                else
                {
                    throw new CryptographicException(
                        $"Key length is not equal to 256 bit, but to {Encoding.UTF8.GetBytes(value).Length * 8}");
                }
            }
        }

        public MagmaProvider()
        {
            
        }

        public MagmaProvider(int sboxseed)
        {
            SeedSbox(sboxseed);
        }

        private void SeedSbox(int seed)
        {
            Random r = new Random(seed);
            for (var i = 0; i < 8; ++i)
            {
                var perm = Enumerable.Range(0, 16).OrderBy(x => r.Next()).ToArray();
                for (var j = 0; j < 16; ++j)
                {
                    _sbox[i, j] = (UInt32) perm[j];
                }
            }
        }

        private UInt32[] GetRoundKeys(byte[] key)
        {
            byte[] keyr = new byte[key.Length];
            UInt32[] subkeys = new UInt32[8];
            Array.Copy(key, keyr, key.Length);
            Array.Reverse(keyr);
            for (int i = 0; i < 8; i++)
            {
                subkeys[i] = BitConverter.ToUInt32(keyr, i * 4);
            }
            Array.Reverse(subkeys);
            return subkeys;
        }

        private UInt32 F(UInt32 input, UInt32 key)
        {
            UInt32 temp = S(input + key);
            return (temp << 11) | (temp >> 21);
        }

        private UInt32 S(UInt32 input)
        {
            UInt32 res = 0;
            res ^= (UInt32) _sbox[0, input & 0x0000000f];
            res ^= (UInt32) (_sbox[1, ((input & 0x000000f0) >> 4)] << 4);
            res ^= (UInt32) (_sbox[2, ((input & 0x00000f00) >> 8)] << 8);
            res ^= (UInt32) (_sbox[3, ((input & 0x0000f000) >> 12)] << 12);
            res ^= (UInt32) (_sbox[4, ((input & 0x000f0000) >> 16)] << 16);
            res ^= (UInt32) (_sbox[5, ((input & 0x00f00000) >> 20)] << 20);
            res ^= (UInt32) (_sbox[6, ((input & 0x0f000000) >> 24)] << 24);
            res ^= (UInt32) (_sbox[7, ((input & 0xf0000000) >> 28)] << 28);
            return res;
        }

        private byte[] Encrypt(byte[] data)
        {
            byte[] datar = new byte[data.Length];
            Array.Copy(data, datar, data.Length);
            Array.Reverse(datar);
            UInt32 a0 = BitConverter.ToUInt32(datar, 0);
            UInt32 a1 = BitConverter.ToUInt32(datar, 4);
            byte[] result = new byte[8];
            for (int i = 0; i < 31; i++)
            {
                int keyIndex = (i < 24) ? i % 8 : 7 - (i % 8);
                UInt32 round = a1 ^ F(a0, _roundkeys[keyIndex]);
                a1 = a0;
                a0 = round;
            }
            a1 = a1 ^ F(a0, _roundkeys[0]);
            Array.Copy(BitConverter.GetBytes(a0), 0, result, 0, 4);
            Array.Copy(BitConverter.GetBytes(a1), 0, result, 4, 4);
            Array.Reverse(result);
            return result;
        }

        private byte[] Decrypt(byte[] data)
        {
            byte[] datar = new byte[data.Length];
            Array.Copy(data, datar, data.Length);
            Array.Reverse(datar);
            UInt32 a0 = BitConverter.ToUInt32(datar, 0);
            UInt32 a1 = BitConverter.ToUInt32(datar, 4);
            byte[] result = new byte[8];
            for (int i = 0; i < 31; i++)
            {
                int keyIndex = (i < 8) ? i % 8 : 7 - (i % 8);
                UInt32 round = a1 ^ F(a0, _roundkeys[keyIndex]);
                a1 = a0;
                a0 = round;
            }
            a1 = a1 ^ F(a0, _roundkeys[0]);
            Array.Copy(BitConverter.GetBytes(a0), 0, result, 0, 4);
            Array.Copy(BitConverter.GetBytes(a1), 0, result, 4, 4);
            Array.Reverse(result);
            return result;
        }

        public Result CBCEncrypt(string input, int ivseed)
        {
            Random rand = new Random(ivseed);
            byte[] iv = new byte[8];
            rand.NextBytes(iv);
            return CBCEncrypt(input, iv);
        }

        public Result CBCEncrypt(string input, byte[] iv)
        {
            if (iv.Length != 8)
            {
                throw new CryptographicException($"Initialization vector length is {iv.Length * 8} bit.");
            }
            List<byte> inputBytes = new List<byte>(Encoding.UTF8.GetBytes(input));
            if (inputBytes.Count % 8 != 0)
            {
                inputBytes.AddRange(new byte[8 - inputBytes.Count % 8]);
            }
            byte[] temp = inputBytes.Take(8).ToArray();
            for (var i = 0; i < 8; ++i)
            {
                temp[i] = (byte) (temp[i] ^ iv[i]);
            }
            temp = Encrypt(temp);
            List<byte> res = new List<byte>(temp);
            for (var i = 1; i < inputBytes.Count / 8; ++i)
            {
                byte[] cur = inputBytes.Skip(i * 8).Take(8).ToArray();
                for (var j = 0; j < 8; ++j)
                {
                    temp[j] = (byte) (cur[j] ^ temp[j]);
                }
                temp = Encrypt(temp);
                res.AddRange(temp);
            }
            return new Result(res.ToArray(), input.Length);
        }

        public string CBCDecrypt(Result input, int ivseed)
        {
            Random rand = new Random(ivseed);
            byte[] iv = new byte[8];
            rand.NextBytes(iv);
            return CBCDecrypt(input, iv);
        }

        public string CBCDecrypt(Result input, byte[] iv)
        {
            if (iv.Length != 8)
            {
                throw new CryptographicException($"Initialization vector length is {iv.Length * 8} bit.");
            }
            List<byte> inputBytes = new List<byte>(input.Encrypted);
            byte[] temp = inputBytes.Take(8).ToArray();
            byte[] decr = Decrypt(temp);
            for (var i = 0; i < 8; ++i)
            {
                decr[i] = (byte) (decr[i] ^ iv[i]);
            }
            List<byte> res = new List<byte>(decr);
            for (var i = 1; i < inputBytes.Count / 8; ++i)
            {
                byte[] cur = inputBytes.Skip(i * 8).Take(8).ToArray();
                decr = Decrypt(cur);
                for (var j = 0; j < 8; ++j)
                {
                    decr[j] = (byte) (decr[j] ^ temp[j]);
                }
                temp = cur;
                res.AddRange(decr);
            }
            return Encoding.UTF8.GetString(res.ToArray()).Substring(0, input.Length);
        }

        public Result CFBEncrypt(string input, int ivseed)
        {
            Random rand = new Random(ivseed);
            byte[] iv = new byte[8];
            rand.NextBytes(iv);
            return CFBEncrypt(input, iv);
        }

        public Result CFBEncrypt(string input, byte[] iv)
        {
            if (iv.Length != 8)
            {
                throw new CryptographicException($"Initialization vector length is {iv.Length * 8} bit.");
            }
            List<byte> inputBytes = new List<byte>(Encoding.UTF8.GetBytes(input));
            if (inputBytes.Count % 8 != 0)
            {
                inputBytes.AddRange(new byte[8 - inputBytes.Count % 8]);
            }
            List<byte> res = new List<byte>();
            byte[] temp = iv;
            for (var i = 0; i < inputBytes.Count / 8; ++i)
            {
                byte[] cur = Encrypt(temp);
                byte[] ot = inputBytes.Skip(i * 8).Take(8).ToArray();
                for (var j = 0; j < 8; ++j)
                {
                    cur[j] = (byte)(cur[j] ^ ot[j]);
                }
                res.AddRange(cur);
                temp = cur;
            }
            return new Result(res.ToArray(), input.Length);
        }

        public string CFBDecrypt(Result input, int ivseed)
        {
            Random rand = new Random(ivseed);
            byte[] iv = new byte[8];
            rand.NextBytes(iv);
            return CFBDecrypt(input, iv);
        }

        public string CFBDecrypt(Result input, byte[] iv)
        {
            if (iv.Length != 8)
            {
                throw new CryptographicException($"Initialization vector length is {iv.Length * 8} bit.");
            }
            List<byte> inputBytes = new List<byte>(input.Encrypted);
            List<byte> res = new List<byte>();
            byte[] temp = iv;
            for (var i = 0; i < inputBytes.Count / 8; ++i)
            {
                byte[] cur = Encrypt(temp);
                byte[] ct = inputBytes.Skip(i * 8).Take(8).ToArray();
                for (var j = 0; j < 8; ++j)
                {
                    cur[j] = (byte)(cur[j] ^ ct[j]);
                }
                res.AddRange(cur);
                temp = ct;
            }
            return Encoding.UTF8.GetString(res.ToArray()).Substring(0, input.Length);
        }

        public Result OFBEncrypt(string input, int ivseed)
        {
            Random rand = new Random(ivseed);
            byte[] iv = new byte[8];
            rand.NextBytes(iv);
            return OFBEncrypt(input, iv);
        }

        public Result OFBEncrypt(string input, byte[] iv)
        {
            if (iv.Length != 8)
            {
                throw new CryptographicException($"Initialization vector length is {iv.Length * 8} bit.");
            }
            List<byte> inputBytes = new List<byte>(Encoding.UTF8.GetBytes(input));
            if (inputBytes.Count % 8 != 0)
            {
                inputBytes.AddRange(new byte[8 - inputBytes.Count % 8]);
            }
            List<byte> res = new List<byte>();
            byte[] temp = iv;
            for (var i = 0; i < inputBytes.Count / 8; ++i)
            {
                byte[] cur = Encrypt(temp);
                temp = (byte[])cur.Clone();
                byte[] ot = inputBytes.Skip(i * 8).Take(8).ToArray();
                for (var j = 0; j < 8; ++j)
                {
                    cur[j] = (byte)(cur[j] ^ ot[j]);
                }
                res.AddRange(cur);
            }
            return new Result(res.ToArray(), input.Length);
        }

        public string OFBDecrypt(Result input, int ivseed)
        {
            Random rand = new Random(ivseed);
            byte[] iv = new byte[8];
            rand.NextBytes(iv);
            return OFBDecrypt(input, iv);
        }

        public string OFBDecrypt(Result input, byte[] iv)
        {
            if (iv.Length != 8)
            {
                throw new CryptographicException($"Initialization vector length is {iv.Length * 8} bit.");
            }
            List<byte> inputBytes = new List<byte>(input.Encrypted);
            List<byte> res = new List<byte>();
            byte[] temp = iv;
            for (var i = 0; i < inputBytes.Count / 8; ++i)
            {
                byte[] cur = Encrypt(temp);
                temp = (byte[])cur.Clone();
                byte[] ct = inputBytes.Skip(i * 8).Take(8).ToArray();
                for (var j = 0; j < 8; ++j)
                {
                    cur[j] = (byte)(cur[j] ^ ct[j]);
                }
                res.AddRange(cur);
            }
            return Encoding.UTF8.GetString(res.ToArray()).Substring(0, input.Length);
        }
    }

    class Result
    {
        public Result(byte[] encrypted, int length)
        {
            this.Encrypted = encrypted;
            this.Length = length;
        }

        public byte[] Encrypted { get; }
        public int Length { get; }
    }
}