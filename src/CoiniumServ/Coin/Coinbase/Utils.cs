#region License
// 
//     MIT License
//
//     CoiniumServ - Crypto Currency Mining Pool Server Software
//     Copyright (C) 2013 - 2017, CoiniumServ Project
//     Hüseyin Uslu, shalafiraistlin at gmail dot com
//     https://github.com/bonesoul/CoiniumServ
// 
//     Permission is hereby granted, free of charge, to any person obtaining a copy
//     of this software and associated documentation files (the "Software"), to deal
//     in the Software without restriction, including without limitation the rights
//     to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//     copies of the Software, and to permit persons to whom the Software is
//     furnished to do so, subject to the following conditions:
//     
//     The above copyright notice and this permission notice shall be included in all
//     copies or substantial portions of the Software.
//     
//     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//     IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//     FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//     AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//     LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//     OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//     SOFTWARE.
// 
#endregion

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using CoiniumServ.Coin.Address.Exceptions;
using CoiniumServ.Cryptology;
using CoiniumServ.Utils.Extensions;
using CoiniumServ.Utils.Numerics;
using Gibbed.IO;
using Serilog;

namespace CoiniumServ.Coin.Coinbase
{
    /// <summary>
    /// Provides helper functions for "serialized CSscript formatting" as defined here: https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki#specification
    /// </summary>
    public static class Utils
    {
        class CashAddrConversionException : Exception
        {
            public CashAddrConversionException()
                : base()
            {
            }
            public CashAddrConversionException(String message)
                : base(message)
            {
            }
        }
        public static class BCHConverter
        {
            private const string CHARSET_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            private const string CHARSET_CASHADDR = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
            // https://play.golang.org/p/zZhIxabo-AQ
            private static readonly sbyte[] DICT_CASHADDR = new sbyte[128]{
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
             1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
        };
            private static readonly sbyte[] DICT_BASE58 = new sbyte[128]{
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
            -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
            22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
            -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1
        };

            private static ulong PolyMod(byte[] input, ulong startValue = 1)
            {
                for (uint i = 0; i < 42; i++)
                {
                    ulong c0 = startValue >> 35;
                    startValue = ((startValue & 0x07ffffffff) << 5) ^ ((ulong)input[i]);
                    if ((c0 & 0x01) != 0)
                    {
                        startValue ^= 0x98f2bc8e61;
                    }
                    if ((c0 & 0x02) != 0)
                    {
                        startValue ^= 0x79b76d99e2;
                    }
                    if ((c0 & 0x04) != 0)
                    {
                        startValue ^= 0xf33e5fb3c4;
                    }
                    if ((c0 & 0x08) != 0)
                    {
                        startValue ^= 0xae2eabe2a8;
                    }
                    if ((c0 & 0x10) != 0)
                    {
                        startValue ^= 0x1e4f43e470;
                    }
                }
                return startValue ^ 1;
            }
            private static byte[] convertBitsEightToFive(byte[] bytes)
            {
                byte[] converted = new byte[34 + 8];
                int a1 = 0, a2 = 0;
                for (; a1 < 32; a1 += 8, a2 += 5)
                {
                    converted[a1] = (byte)(bytes[a2] >> 3);
                    converted[a1 + 1] = (byte)(bytes[a2] % 8 << 2 | bytes[a2 + 1] >> 6);
                    converted[a1 + 2] = (byte)(bytes[a2 + 1] % 64 >> 1);
                    converted[a1 + 3] = (byte)(bytes[a2 + 1] % 2 << 4 | bytes[a2 + 2] >> 4);
                    converted[a1 + 4] = (byte)(bytes[a2 + 2] % 16 << 1 | bytes[a2 + 3] >> 7);
                    converted[a1 + 5] = (byte)(bytes[a2 + 3] % 128 >> 2);
                    converted[a1 + 6] = (byte)(bytes[a2 + 3] % 4 << 3 | bytes[a2 + 4] >> 5);
                    converted[a1 + 7] = (byte)(bytes[a2 + 4] % 32);
                }
                converted[a1] = (byte)(bytes[a2] >> 3);
                converted[a1 + 1] = (byte)(bytes[a2] % 8 << 2);
                return converted;
            }
            private static byte[] convertBitsFiveToEight(byte[] bytes)
            {
                byte[] converted = new byte[(1 + 20) + 4];
                int a1 = 0, a2 = 0;
                for (; a2 < 32; a1 += 5, a2 += 8)
                {
                    converted[a1] = (byte)(bytes[a2] << 3 | bytes[a2 + 1] >> 2);
                    converted[a1 + 1] = (byte)(bytes[a2 + 1] % 4 << 6 | bytes[a2 + 2] << 1 | bytes[a2 + 3] >> 4);
                    converted[a1 + 2] = (byte)(bytes[a2 + 3] % 16 << 4 | bytes[a2 + 4] >> 1);
                    converted[a1 + 3] = (byte)(bytes[a2 + 4] % 2 << 7 | bytes[a2 + 5] << 2 | bytes[a2 + 6] >> 3);
                    converted[a1 + 4] = (byte)(bytes[a2 + 6] % 8 << 5 | bytes[a2 + 7]);
                }
                converted[a1] = (byte)(bytes[a2] << 3 | bytes[a2 + 1] >> 2);
                if (bytes[a2 + 1] % 4 != 0)
                    throw new CashAddrConversionException("Invalid CashAddr.");
                return converted;
            }

            public static string oldAddrToCashAddr(string oldAddress, out bool isP2PKH, out bool mainnet)
            {
                // BigInteger wouldn't be needed, but that would result in the use a MIT License
                BigInteger address = new BigInteger(0);
                BigInteger baseFiftyEight = new BigInteger(58);
                for (int x = 0; x < oldAddress.Length; x++)
                {
                    int value = DICT_BASE58[oldAddress[x]];
                    if (value != -1)
                    {
                        address = BigInteger.Multiply(address, baseFiftyEight);
                        address = BigInteger.Add(address, new BigInteger(value));
                    }
                    else
                    {
                        throw new CashAddrConversionException("Address contains unexpected character.");
                    }
                }
                int numZeros = 0;
                for (; (numZeros < oldAddress.Length) && (oldAddress[numZeros] == Convert.ToChar("1")); numZeros++) { }
                byte[] addrBytes = address.ToByteArray();
                Array.Reverse(addrBytes);
                // Reminder, addrBytes was converted from BigInteger. So the first byte,
                // the sign byte should be skipped, **if exists**
                if (addrBytes[0] == 0)
                {
                    // because of 0xc4
                    var temp = new List<byte>(addrBytes);
                    temp.RemoveAt(0);
                    addrBytes = temp.ToArray();
                }
                if (numZeros > 0)
                {
                    var temp = new List<byte>(addrBytes);
                    for (; numZeros != 0; numZeros--)
                        temp.Insert(0, 0);
                    addrBytes = temp.ToArray();
                }
                if (addrBytes.Length != 25)
                {
                    throw new CashAddrConversionException("Address to be decoded is shorter or longer than expected!");
                }
                switch (addrBytes[0])
                {
                    case 0x00:
                        isP2PKH = true;
                        mainnet = true;
                        break;
                    case 0x05:
                        isP2PKH = false;
                        mainnet = true;
                        break;
                    case 0x6f:
                        isP2PKH = true;
                        mainnet = false;
                        break;
                    case 0xc4:
                        isP2PKH = false;
                        mainnet = false;
                        break;
                    case 0x1c:
                    // BitPay P2PKH, obsolete!
                    case 0x28:
                    // BitPay P2SH, obsolete!
                    default:
                        throw new CashAddrConversionException("Unexpected address byte.");
                }
                if (addrBytes.Length != 25)
                {
                    throw new CashAddrConversionException("Old address is longer or shorter than expected.");
                }
                SHA256 hasher = SHA256Managed.Create();
                byte[] checksum = hasher.ComputeHash(hasher.ComputeHash(addrBytes, 0, 21));
                if (addrBytes[21] != checksum[0] || addrBytes[22] != checksum[1] || addrBytes[23] != checksum[2] || addrBytes[24] != checksum[3])
                    throw new CashAddrConversionException("Address checksum doesn't match. Have you made a mistake while typing it?");
                addrBytes[0] = (byte)(isP2PKH ? 0x00 : 0x08);
                byte[] cashAddr = convertBitsEightToFive(addrBytes);
                var ret = new System.Text.StringBuilder(mainnet ? "bitcoincash:" : "bchtest:");
                // https://play.golang.org/p/sM_CE4AQ7Vp
                ulong mod = PolyMod(cashAddr, (ulong)(mainnet ? 1058337025301 : 584719417569));
                for (int i = 0; i < 8; ++i)
                {
                    cashAddr[i + 34] = (byte)((mod >> (5 * (7 - i))) & 0x1f);
                }
                for (int i = 0; i < cashAddr.Length; i++)
                {
                    ret.Append(CHARSET_CASHADDR[cashAddr[i]]);
                }
                return ret.ToString();
            }
            public static string cashAddrToOldAddr(string cashAddr, out bool isP2PKH, out bool mainnet)
            {
                cashAddr = cashAddr.ToLower();
                if (cashAddr.Length != 54 && cashAddr.Length != 42 && cashAddr.Length != 50)
                {
                    if (cashAddr.StartsWith("bchreg:"))
                        throw new CashAddrConversionException("Decoding RegTest addresses is not implemented.");
                    throw new CashAddrConversionException("Address to be decoded is longer or shorter than expected.");
                }
                int afterPrefix;
                if (cashAddr.StartsWith("bitcoincash:"))
                {
                    mainnet = true;
                    afterPrefix = 12;
                }
                else if (cashAddr.StartsWith("bchtest:"))
                {
                    mainnet = false;
                    afterPrefix = 8;
                }
                else if (cashAddr.StartsWith("bchreg:"))
                    throw new CashAddrConversionException("Decoding RegTest addresses is not implemented.");
                else
                {
                    if (cashAddr.IndexOf(":") == -1)
                    {
                        mainnet = true;
                        afterPrefix = 0;
                    }
                    else
                        throw new CashAddrConversionException("Unexpected colon character.");
                }
                int max = afterPrefix + 42;
                if (max != cashAddr.Length)
                {
                    throw new CashAddrConversionException("Address to be decoded is longer or shorter than expected.");
                }
                byte[] decodedBytes = new byte[42];
                for (int i = afterPrefix; i < max; i++)
                {
                    int value = DICT_CASHADDR[cashAddr[i]];
                    if (value != -1)
                    {
                        decodedBytes[i - afterPrefix] = (byte)value;
                    }
                    else
                    {
                        throw new CashAddrConversionException("Address contains unexpected character.");
                    }
                }
                if (PolyMod(decodedBytes, (ulong)(mainnet ? 1058337025301 : 584719417569)) != 0)
                    throw new CashAddrConversionException("Address checksum doesn't match. Have you made a mistake while typing it?");
                decodedBytes = convertBitsFiveToEight(decodedBytes);
                switch (decodedBytes[0])
                {
                    case 0x00:
                        isP2PKH = true;
                        break;
                    case 0x08:
                        isP2PKH = false;
                        break;
                    default:
                        throw new CashAddrConversionException("Unexpected address byte.");
                }
                if (mainnet && isP2PKH)
                    decodedBytes[0] = 0x00;
                else if (mainnet && !isP2PKH)
                    decodedBytes[0] = 0x05;
                else if (!mainnet && isP2PKH)
                    decodedBytes[0] = 0x6f;
                else
                    // Warning! Bigger than 0x80.
                    decodedBytes[0] = 0xc4;
                SHA256 hasher = SHA256Managed.Create();
                byte[] checksum = hasher.ComputeHash(hasher.ComputeHash(decodedBytes, 0, 21));
                decodedBytes[21] = checksum[0];
                decodedBytes[22] = checksum[1];
                decodedBytes[23] = checksum[2];
                decodedBytes[24] = checksum[3];
                System.Text.StringBuilder ret = new System.Text.StringBuilder(40);
                for (int numZeros = 0; numZeros < 25 && decodedBytes[numZeros] == 0; numZeros++)
                    ret.Append("1");
                {
                    var temp = new List<byte>(decodedBytes);
                    // for 0xc4
                    temp.Insert(0, 0);
                    temp.Reverse();
                    decodedBytes = temp.ToArray();
                }

                byte[] retArr = new byte[40];
                int retIdx = 0;
                BigInteger baseChanger = BigInteger.Abs(new BigInteger(decodedBytes));
                BigInteger baseFiftyEight = new BigInteger(58);
                BigInteger modulo = new BigInteger();
                while (!baseChanger.IsZero)
                {
                    baseChanger = BigInteger.DivRem(baseChanger, baseFiftyEight, out modulo);
                    retArr[retIdx++] = (byte)modulo;
                }
                for (retIdx--; retIdx >= 0; retIdx--)
                    ret.Append(CHARSET_BASE58[retArr[retIdx]]);
                return ret.ToString();
            }
        }

        /// <summary>
        /// For POW coins - used to format wallet address for use in generation transaction's output
        /// </summary>
        /// <param name="address"></param>
        /// <example>
        /// nodejs: https://github.com/zone117x/node-stratum-pool/blob/dfad9e58c661174894d4ab625455bb5b7428881c/lib/util.js#L264
        /// nodejs: https://codio.com/raistlinthewiz/bitcoin-coinbase-serializer-wallet-address-to-script
        /// </example>
        /// <returns></returns>
        public static byte[] CoinAddressToScript(string address)
        {
            byte[] decoded = new byte[] { };

            try
            {
                decoded = Address.Base58.Decode(address);

                var pubkey = decoded;
                byte versionKey = decoded[0];
                if (decoded.Length == 25)
                {
                    pubkey = decoded.Slice(1, -4);
                }

                byte[] result;

                using (var stream = new MemoryStream())
                {
                    stream.WriteValueU8(0x76);
                    stream.WriteValueU8(0xa9);
                    stream.WriteValueU8(0x14);
                    stream.WriteBytes(pubkey);
                    stream.WriteValueU8(0x88);
                    stream.WriteValueU8(0xac);

                    result = stream.ToArray();
                }

                return result;
            }
            catch (AddressFormatException)
            {
                try
                {
                    decoded = Converter.DecodeBech32(address, out byte witnessVersion, out byte isP2PKH, out bool mainnet);
                    var final = new List<byte>();
                    final.Add(0x00);
                    final.Add(0x14);
                    final.AddRange(decoded);
                    return final.ToArray();
                }
                catch
                {
                    string converted = BCHConverter.cashAddrToOldAddr(address, out bool isP2PKH, out bool mainnet);
                    decoded = Address.Base58.Decode(converted);
                    var final = new List<byte>();
                    final.Add(0);
                    final.Add(0x14);
                    final.AddRange(decoded);
                    return final.ToArray();
                }
            }
        }

        /// <summary>
        /// For POS coins - used to format wallet address pubkey to use in generation transaction's output.
        /// </summary>
        /// <param name="key"></param>
        /// <example>
        /// nodejs: https://github.com/zone117x/node-stratum-pool/blob/3586ec0d7374b2acc5a72d5ef597da26f0e39d54/lib/util.js#L243
        /// nodejs: http://runnable.com/me/VCFHE0RrZnwbsQ6y
        /// </example>
        /// <returns></returns>
        public static byte[] PubKeyToScript(string key)
        {
            var pubKey = key.HexToByteArray();

            if (pubKey.Length != 33)
            {
                Log.Error("invalid pubkey length for {0:l}", key);
                return null;
            }

            byte[] result;

            using (var stream = new MemoryStream())
            {
                stream.WriteValueU8(0x21);
                stream.WriteBytes(pubKey);
                stream.WriteValueU8(0xac);
                result = stream.ToArray();
            }

            return result;
        }

        /// <summary>
        /// Hashes the coinbase.
        /// </summary>
        /// <param name="coinbase"></param>
        /// <param name="doubleDigest"></param>
        /// <returns></returns>
        public static Hash HashCoinbase(byte[] coinbase, bool doubleDigest = true)
        {
            return doubleDigest ? coinbase.DoubleDigest() : coinbase.Digest();

            // TODO: fix this according - https://github.com/zone117x/node-stratum-pool/blob/eb4b62e9c4de8a8cde83c2b3756ca1a45f02b957/lib/jobManager.js#L69
        }

        /// <summary>
        /// Used to convert getblocktemplate bits field into target if target is not included.
        //// More info: https://en.bitcoin.it/wiki/Target
        /// </summary>
        /// <param name="bits"></param>
        /// <returns></returns>
        public static BigInteger BigIntFromBitsHex(this string bits)
        {
            // TODO: implement a test for it!

            return bits.HexToByteArray().BigIntFromBitsBuffer();
        }

        public static BigInteger BigIntFromBitsBuffer(this byte[] buffer)
        {
            // TODO: implement a test for it!

            var numBytes = Convert.ToByte(buffer.Take(1));
            var bigIntBits = new BigInteger(buffer.Slice(1, buffer.Length - 1));

            var multiplier = new BigInteger(2 ^ 8 * (numBytes - 3));
            var target = BigInteger.Multiply(bigIntBits, multiplier);

            return target;
        }
    }



    class Bech32ConversionException : Exception
    {
        public Bech32ConversionException()
            : base()
        {
        }
        public Bech32ConversionException(String message)
            : base(message)
        {
        }
    }
    public static class Converter
    {
        private const string CHARSET_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        // https://play.golang.org/p/zZhIxabo-AQ
        private static readonly sbyte[] DICT_BECH32 = new sbyte[128]{
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
             1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
        };
        private static uint PolyMod(byte[] input)
        {
            uint startValue = 1;
            for (uint i = 0; i < input.Length; i++)
            {
                uint c0 = startValue >> 25;
                startValue = (uint)(((startValue & 0x1ffffff) << 5) ^
                    (input[i]) ^
                    (-((c0 >> 0) & 1) & 0x3b6a57b2) ^
                    (-((c0 >> 1) & 1) & 0x26508e6d) ^
                    (-((c0 >> 2) & 1) & 0x1ea119fa) ^
                    (-((c0 >> 3) & 1) & 0x3d4233dd) ^
                    (-((c0 >> 4) & 1) & 0x2a1462b3));
            }
            return startValue;
        }
        private static void hrpExpand(string hrp, byte[] ret)
        {
            int len = hrp.Length;
            //byte[] ret = new byte[len * 2 + 1];
            for (int i = 0; i < len; i++)
            {
                ret[i] = (byte)(hrp[i] >> 5);
            }
            ret[len] = 0;
            for (int i = 0; i < len; i++)
            {
                ret[len + 1 + i] = (byte)(hrp[i] & 31);
            }
        }
        private static byte[] createChecksum(string hrp, byte[] data, int dataLen)
        {
            int hrpLen = hrp.Length * 2 + 1;
            byte[] values = new byte[hrpLen + dataLen + 6];
            hrpExpand(hrp, values);
            System.Buffer.BlockCopy(data, 0, values, hrpLen, dataLen);
            uint mod = PolyMod(values) ^ 1;
            byte[] ret = new byte[6];
            for (int i = 0; i < 6; i++)
            {
                ret[i] = (byte)((mod >> (5 * (5 - i))) & 31);
            }
            return ret;
        }
        private static bool verifyChecksum(string hrp, byte[] dataWithChecksum)
        {
            byte[] values = new byte[hrp.Length * 2 + 1 + dataWithChecksum.Length];
            hrpExpand(hrp, values);
            System.Buffer.BlockCopy(dataWithChecksum, 0, values, hrp.Length * 2 + 1, dataWithChecksum.Length);
            var polyMod = PolyMod(values);
            return polyMod == 1 || polyMod == 0x2bc830a3;
        }
        private static int convertBits(byte[] bytes, int inBits, uint outBits, bool pad, byte[] converted, int inPos, int outPos, int len)
        {
            //byte[] converted = new byte[bytes.Length * inBits / outBits + (bytes.Length * inBits % outBits != 0 ? 1 : 0)];
            uint bits = 0, maxv = (uint)((1 << (int)outBits) - 1), val = 0;
            //int len = bytes.Length - inPos;
            while (len-- != 0)
            {
                val = (val << inBits) | bytes[inPos++];
                bits += (uint)inBits;
                while (bits >= outBits)
                {
                    bits -= outBits;
                    converted[outPos++] = (byte)((val >> (int)bits) & maxv);
                }
            }
            if (pad)
            {
                if (bits != 0)
                {
                    converted[outPos++] = (byte)((val << (int)(outBits - bits)) & maxv);
                }
            }
            else if ((((val << (int)(outBits - bits)) & maxv) != 0) || bits >= inBits)
            {
                throw new Bech32ConversionException("Bit conversion error!" + bits + " " + inBits + " " + ((val << (int)(outBits - bits)) & maxv));
            }
            return outPos;
        }

        // Witness = witness version byte + 2-40 byte witness program
        // witness version can be only 0, currently
        // witness program is 20-byte RIPEMD160(SHA256(pubkey)) for P2WPKH
        // and 32-byte SHA256(script) for P2WSH
        // https://bitcoin.stackexchange.com/a/71219
        public static string EncodeBech32(byte witnessVersion, byte[] witnessProgram, bool isP2PKH, bool mainnet)
        {
            if (witnessProgram.Length < 3 || witnessProgram.Length > 41)
            {
                throw new Bech32ConversionException("Invalid witness program!");
            }
            System.Text.StringBuilder ret;
            byte[] data = new byte[80];
            int len = convertBits(witnessProgram, 8, 5, true, data, 0, 1, witnessProgram.Length);
            data[0] = witnessVersion;
            byte[] checksum;
            if (mainnet)
            {
                ret = new System.Text.StringBuilder("bc", 75); ;
                checksum = createChecksum("bc", data, len);
            }
            else
            {
                ret = new System.Text.StringBuilder("tb", 75); ;
                checksum = createChecksum("tb", data, len);
            }
            ret.Append('1');
            for (int i = 0; i < len; i++)
            {
                ret.Append((char)data[i]);
            }
            for (int i = 3, k = len + 3; i < k; i++)
            {
                ret[i] = CHARSET_BECH32[ret[i]];
            }
            for (int i = 0; i < 6; i++)
            {
                ret.Append(CHARSET_BECH32[checksum[i]]);
            }
            return ret.ToString();
        }
        // Returns the witnessProgram
        // isP2PKH is 0 for P2PKH, 1 for P2SH, 2 for "couldn't determine"
        public static byte[] DecodeBech32(string addr, out byte witnessVersion, out byte isP2PKH, out bool mainnet)
        {
            string addr2 = addr.ToLower();
            string hrp = "bc";

            string[] parts = addr.Split(new[] { '1', ':' });
            if(parts.Length != 2)
            {
                throw new Bech32ConversionException("Invalid Bech32 address!");
            }

            hrp = parts[0];
            mainnet = addr2.StartsWith("b");

            witnessVersion = 0;
            int dataLen = addr2.Length - (hrp.Length + 1);
            byte[] data = new byte[dataLen];
            for (int i = 0; i < dataLen; i++)
            {
                data[i] = (byte)addr2[(hrp.Length+1) + i];
            }
            sbyte err = 0;
            for (int i = 0; i < dataLen; i++)
            {
                sbyte k = DICT_BECH32[data[i]];
                err |= k;
                data[i] = unchecked((byte)k);
            }
            if (err == -1 || !verifyChecksum(hrp, data))
            {
                throw new Bech32ConversionException("Invalid Bech32 address!");
            }
            byte[] decoded = new byte[60];
            int decodedLen = convertBits(data, 5, 8, false, decoded, 1, 0, dataLen - 1 - 6);
            switch (decodedLen)
            {
                case 20:
                    isP2PKH = 0;
                    break;
                case 32:
                    isP2PKH = 1;
                    break;
                default:
                    isP2PKH = 2;
                    break;
            }
            byte[] final = new byte[decodedLen];
            System.Buffer.BlockCopy(decoded, 0, final, 0, decodedLen);
            return final;
        }
    }
}
