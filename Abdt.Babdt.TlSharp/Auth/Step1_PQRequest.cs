using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Abdt.Babdt.TlSharp.MTProto;
using Abdt.Babdt.TlSharp.MTProto.Crypto;

namespace Abdt.Babdt.TlSharp.Auth
{
  public class Step1_PQRequest
  {
    private byte[] nonce;

    public Step1_PQRequest() => this.nonce = new byte[16];

    public byte[] ToBytes()
    {
      new Random().NextBytes(this.nonce);
      using (MemoryStream output = new MemoryStream())
      {
        using (BinaryWriter binaryWriter = new BinaryWriter((Stream) output))
        {
          binaryWriter.Write(1615239032);
          binaryWriter.Write(this.nonce);
          return output.ToArray();
        }
      }
    }

    public Step1_Response FromBytes(byte[] bytes)
    {
      List<byte[]> numArrayList = new List<byte[]>();
      using (MemoryStream input = new MemoryStream(bytes, false))
      {
        using (BinaryReader binaryReader = new BinaryReader((Stream) input))
        {
          int num1 = binaryReader.ReadInt32();
          if (num1 != 85337187)
            throw new InvalidOperationException(string.Format("invalid response code: {0}", (object) num1));
          byte[] numArray1 = ((IEnumerable<byte>) binaryReader.ReadBytes(16)).SequenceEqual<byte>((IEnumerable<byte>) this.nonce) ? binaryReader.ReadBytes(16) : throw new InvalidOperationException("invalid nonce from server");
          BigInteger bigInteger = new BigInteger(1, Serializers.Bytes.read(binaryReader));
          int num2 = binaryReader.ReadInt32();
          if (num2 != 481674261)
            throw new InvalidOperationException(string.Format("Invalid vector constructor number {0}", (object) num2));
          int num3 = binaryReader.ReadInt32();
          for (int index = 0; index < num3; ++index)
          {
            byte[] numArray2 = binaryReader.ReadBytes(8);
            numArrayList.Add(numArray2);
          }
          return new Step1_Response()
          {
            Fingerprints = numArrayList,
            Nonce = this.nonce,
            Pq = bigInteger,
            ServerNonce = numArray1
          };
        }
      }
    }
  }
}
