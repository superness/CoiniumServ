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
using System.Linq;
using CoiniumServ.Utils.Extensions;
using CoiniumServ.Utils.Helpers;
using CoiniumServ.Utils.Numerics;

namespace CoiniumServ.Cryptology.Merkle
{

    public class MerkleRoot
    {

        public static string merkle(string[] transactions)
        {
            while (true)
            {
                if (transactions.Length == 1) return transactions[0];
                List<string> newHashList = new List<string>();
                int len = (transactions.Length % 2 != 0) ? transactions.Length - 1 : transactions.Length;
                for (int i = 0; i < len; i += 2) newHashList.Add(Hash2(transactions[i], transactions[i + 1]));
                if (len < transactions.Length) newHashList.Add(Hash2(transactions[transactions.Length - 1], transactions[transactions.Length - 1]));
                transactions = newHashList.ToArray();
            }
        }


        static string Hash2(string a, string b)
        {
            byte[] a1 = Enumerable.Range(0, a.Length / 2).Select(x => Convert.ToByte(a.Substring(x * 2, 2), 16)).ToArray();
            Array.Reverse(a1);
            byte[] b1 = Enumerable.Range(0, b.Length / 2).Select(x => Convert.ToByte(b.Substring(x * 2, 2), 16)).ToArray();
            Array.Reverse(b1);
            var c = a1.Concat(b1).ToArray();
            var sha256 = System.Security.Cryptography.SHA256.Create();
            byte[] firstHash = sha256.ComputeHash(c);
            byte[] hashOfHash = sha256.ComputeHash(firstHash);
            Array.Reverse(hashOfHash);
            return BitConverter.ToString(hashOfHash).Replace("-", "").ToLower();
        }

    }



    /// <summary>
    /// Merkle tree builder.
    /// </summary>
    /// <remarks>
    /// To get a better understanding of merkle trees check: http://www.youtube.com/watch?v=gUwXCt1qkBU#t=09m09s 
    /// </remarks>
    /// <specification>https://en.bitcoin.it/wiki/Protocol_specification#Merkle_Trees</specification>
    /// <example>
    /// Python implementation: http://runnable.com/U3HnDaMrJFk3gkGW/bitcoin-block-merkle-root-2-for-python
    /// Original implementation: https://code.google.com/p/bitcoinsharp/source/browse/src/Core/Block.cs#330
    /// </example>
    public class MerkleTree : IMerkleTree
    {
        /// <summary>
        /// The steps in tree.
        /// </summary>
        public IList<byte[]> Steps { get; private set; }

        private IList<byte[]> _hashes;
        public IEnumerable<byte[]> Hashes => _hashes.ToArray();

        /// <summary>
        /// List of hashes, will be used for calculation of merkle root. 
        /// <remarks>This is not a list of all transactions, it only contains prepared hashes of steps of merkle tree algorithm. Please read some materials (http://en.wikipedia.org/wiki/Hash_tree) for understanding how merkle trees calculation works. (http://mining.bitcoin.cz/stratum-mining)</remarks>
        /// <remarks>The coinbase transaction is hashed against the merkle branches to build the final merkle root.</remarks>
        /// </summary>
        public List<string> Branches
        {
            get
            {
                return Steps.Select(step => step.ToHexString()).ToList();
            }
        }

        /// <summary>
        /// Creates a new merkle-tree instance.
        /// </summary>
        /// <param name="hashList"></param>
        public MerkleTree(IEnumerable<byte[]> hashList)
        {
            Steps = CalculateSteps(hashList);
            _hashes = hashList.ToList();
        }       

        /// <summary>
        /// 
        /// </summary>
        /// <example>
        /// python: http://runnable.com/U3jqtyYUmAUxtsSS/bitcoin-block-merkle-root-python
        /// nodejs: https://github.com/zone117x/node-stratum-pool/blob/master/lib/merkleTree.js#L9
        /// </example>
        /// <param name="hashList"></param>
        /// <returns></returns>
        private IList<byte[]> CalculateSteps(IEnumerable<byte[]> hashList)
        {
            var steps = new List<byte[]>();

            var L = new List<byte[]>();
            L.AddRange(hashList);

            var startL = 2;
            var Ll = L.Count;

            if (Ll > 0)
            {
                while (true)
                {
                    if (Ll == 1)
                        break;

                    steps.Add(L[1]);

                    if (Ll%2 == 1)
                        L.Add(L[L.Count - 1]);

                    var Ld = new List<byte[]>();

                    foreach (int i in Range.From(startL).To(Ll).WithStepSize(2))
                    {
                        Ld.Add(MerkleJoin(L[i], L[i + 1]));
                    }

                    L = new List<byte[]> {null};
                    L.AddRange(Ld);
                    Ll = L.Count;
                }
            }
            return steps;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <example>
        /// nodejs: https://github.com/zone117x/node-stratum-pool/blob/master/lib/merkleTree.js#L11
        /// </example>
        /// <param name="hash1"></param>
        /// <param name="hash2"></param>
        /// <returns></returns>
        private byte[] MerkleJoin(byte[] hash1, byte[] hash2)
        {
            var joined = hash1.Append(hash2);
            var dHashed = joined.DoubleDigest();
            return dHashed;
        }

        public byte[] WithFirst(byte[] first)
        {
            var withFirst = _hashes.Prepend(first);

            return MerkleTreeCalculator.ComputeMerkleRoot(withFirst.Select(h => new BigInteger(h)).ToList(), out bool mutated).ToByteArray();

            //return MerkleRoot.merkle(withFirst.Select(h => h.ToHexString()).ToArray()).HexToByteArray();

            foreach (var step in Steps)
            {
                first = first.Append(step).DoubleDigest();
            }

            return first;
        }
    }


    public class MerkleTreeCalculator
    {
        public static BigInteger ComputeMerkleRoot(List<BigInteger> hashes, out bool mutated)
        {
            mutated = false;
            while (hashes.Count > 1)
            {
                if (hashes.Count % 2 == 1)
                    hashes.Add(hashes.Last());  // Duplicate the last element if odd number of hashes

                List<BigInteger> newHashes = new List<BigInteger>();

                for (int i = 0; i < hashes.Count; i += 2)
                {
                    if (hashes[i] == hashes[i + 1])
                        mutated = true;

                    BigInteger hashPair = HashTwice(hashes[i], hashes[i + 1]);
                    newHashes.Add(hashPair);
                }

                hashes = newHashes;
            }

            return hashes.Count > 0 ? hashes[0] : BigInteger.Zero;
        }

        private static BigInteger HashTwice(BigInteger left, BigInteger right)
        {
            using (System.Security.Cryptography.SHA256 sha256 = System.Security.Cryptography.SHA256.Create())
            {
                byte[] input = left.ToByteArray().Concat(right.ToByteArray()).ToArray();
                byte[] firstHash = sha256.ComputeHash(input);
                byte[] secondHash = sha256.ComputeHash(firstHash);
                return new BigInteger(secondHash);
            }
        }
    }

}
