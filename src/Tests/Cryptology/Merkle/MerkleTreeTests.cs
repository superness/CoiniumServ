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

using System.Linq;
using CoiniumServ.Cryptology.Merkle;
using CoiniumServ.Daemon;
using CoiniumServ.Daemon.Responses;
using CoiniumServ.Transactions.Utils;
using CoiniumServ.Utils.Extensions;
using Newtonsoft.Json;
using Should.Fluent;
using Xunit;

namespace CoiniumServ.Tests.Cryptology.Merkle
{
    public class MerkleTreeTests
    {
        // object mocks.
        private IBlockTemplate _blockTemplate;

        [Fact]
        public void TestWithZeroTransaction()
        {
            /*
                coinbaseHash: a3291f854e60860ec74caf232ed34f98d0ff447dd7d38dbd7d451462b4b6f263
                merkle-tree withFirst() - first: a3291f854e60860ec74caf232ed34f98d0ff447dd7d38dbd7d451462b4b6f263
                steps: []
                final: a3291f854e60860ec74caf232ed34f98d0ff447dd7d38dbd7d451462b4b6f263
                merkleRoot: 63f2b6b46214457dbd8dd3d77d44ffd0984fd32e23af4cc70e86604e851f29a3
             */

            // block template
            const string json = "{\"result\":{\"version\":2,\"previousblockhash\":\"1a47638fd58c3b90cc3b2a7f1973dcdf545be4474d2157af28ad6ce7767acb09\",\"transactions\":[],\"coinbaseaux\":{\"flags\":\"062f503253482f\"},\"coinbasevalue\":5000000000,\"target\":\"000000ffff000000000000000000000000000000000000000000000000000000\",\"mintime\":1403563551,\"mutable\":[\"time\",\"transactions\",\"prevblock\"],\"noncerange\":\"00000000ffffffff\",\"sigoplimit\":20000,\"sizelimit\":1000000,\"curtime\":1403563962,\"bits\":\"1e00ffff\",\"height\":313498},\"error\":null,\"id\":1}";
            var blockTemplateObject = JsonConvert.DeserializeObject<DaemonResponse<BlockTemplate>>(json);
            _blockTemplate = blockTemplateObject.Result;

            var hashList = _blockTemplate.Transactions.GetHashList();
            var tree = new MerkleTree(hashList);

            // steps counts should be zero
            //tree.Steps.Count.Should().Equal(0);
            //tree.Branches.Count.Should().Equal(0);

            // calculate the result
            var result = tree.WithFirst("a3291f854e60860ec74caf232ed34f98d0ff447dd7d38dbd7d451462b4b6f263".HexToByteArray());
            var root = result.ReverseBuffer();

            // check the result and root
            result.ToHexString().Should().Equal("a3291f854e60860ec74caf232ed34f98d0ff447dd7d38dbd7d451462b4b6f263");
            root.ToHexString().Should().Equal("63f2b6b46214457dbd8dd3d77d44ffd0984fd32e23af4cc70e86604e851f29a3");
        }

        [Fact]
        public void TestWithSingleTransaction()
        {
            /* 
                coinbaseHash: 357deb5f66416ac7bd10d21557f50d358d85581c4c2e725dc1113cd277869a1a
                merkle-tree withFirst() - first: 357deb5f66416ac7bd10d21557f50d358d85581c4c2e725dc1113cd277869a1a
                data: [null,[53,242,80,55,174,213,162,52,45,204,185,251,93,86,89,207,225,108,2,213,196,226,105,86,44,36,81,78,26,93,182,160]]
                steps: [[53,242,80,55,174,213,162,52,45,204,185,251,93,86,89,207,225,108,2,213,196,226,105,86,44,36,81,78,26,93,182,160]]
                => f: 357deb5f66416ac7bd10d21557f50d358d85581c4c2e725dc1113cd277869a1a step: 35f25037aed5a2342dccb9fb5d5659cfe16c02d5c4e269562c24514e1a5db6a0 buffer.contact([f,s]): 357deb5f66416ac7bd10d21557f50d358d85581c4c2e725dc1113cd277869a1a35f25037aed5a2342dccb9fb5d5659cfe16c02d5c4e269562c24514e1a5db6a0
                |-> new f: da307cebe47b9c45046ef74cb4d800d8c90ad8bf1b542d501966fb2dae44b129
                final: da307cebe47b9c45046ef74cb4d800d8c90ad8bf1b542d501966fb2dae44b129
                merkleRoot: 29b144ae2dfb6619502d541bbfd80ac9d800d8b44cf76e04459c7be4eb7c30da
            */

            // block template
            const string json = "{\"result\":{\"version\":2,\"previousblockhash\":\"316b5be0c2cb6903170c1b470fac606c9ecedd149233eaabc1b453843ba408f6\",\"transactions\":[{\"data\":\"sdaasdf\",\"hash\":\"a0b65d1a4e51242c5669e2c4d5026ce1cf59565dfbb9cc2d34a2d5ae3750f235\",\"depends\":[],\"fee\":1500000,\"sigops\":2}],\"coinbaseaux\":{\"flags\":\"062f503253482f\"},\"coinbasevalue\":5001500000,\"target\":\"00000048d4f70000000000000000000000000000000000000000000000000000\",\"mintime\":1403699336,\"mutable\":[\"time\",\"transactions\",\"prevblock\"],\"noncerange\":\"00000000ffffffff\",\"sigoplimit\":20000,\"sizelimit\":1000000,\"curtime\":1403699784,\"bits\":\"1d48d4f7\",\"height\":315219},\"error\":null,\"id\":1}";
            var blockTemplateObject = JsonConvert.DeserializeObject<DaemonResponse<BlockTemplate>>(json);
            _blockTemplate = blockTemplateObject.Result;

            var hashList = _blockTemplate.Transactions.GetHashList();
            var tree = new MerkleTree(hashList);

            // tests steps
            //tree.Steps.Count.Should().Equal(1);
            //tree.Branches.Count.Should().Equal(1);
            //tree.Steps.First().ToHexString().Should().Equal("35f25037aed5a2342dccb9fb5d5659cfe16c02d5c4e269562c24514e1a5db6a0");

            // check root
            var root = tree.WithFirst("357deb5f66416ac7bd10d21557f50d358d85581c4c2e725dc1113cd277869a1a".HexToByteArray()).ReverseBuffer();
            root.ToHexString().Should().Equal("29b144ae2dfb6619502d541bbfd80ac9d800d8b44cf76e04459c7be4eb7c30da");
        }

        [Fact]
        public void TestWithSingleTransaction2()
        {
            var hashList = new[] { "a0b65d1a4e51242c5669e2c4d5026ce1cf59565dfbb9cc2d34a2d5ae3750f235" }.Select(hash => hash.HexToByteArray().ReverseBuffer());
            var tree = new MerkleTree(hashList);

            // check root
            var root = tree.WithFirst("357deb5f66416ac7bd10d21557f50d358d85581c4c2e725dc1113cd277869a1a".HexToByteArray()).ReverseBuffer();
            root.ToHexString().Should().Equal("29b144ae2dfb6619502d541bbfd80ac9d800d8b44cf76e04459c7be4eb7c30da");
        }
    }
}
