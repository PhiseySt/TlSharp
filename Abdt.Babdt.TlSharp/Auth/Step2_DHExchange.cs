using System;
using System.Collections.Generic;
using System.IO;
using Abdt.Babdt.TlSharp.MTProto;
using Abdt.Babdt.TlSharp.MTProto.Crypto;

namespace Abdt.Babdt.TlSharp.Auth
{
  public class Step2_DHExchange
  {
    public byte[] newNonce;

    public Step2_DHExchange() => this.newNonce = new byte[32];

    public byte[] ToBytes(
      byte[] nonce,
      byte[] serverNonce,
      List<byte[]> fingerprints,
      BigInteger pq)
    {
      new Random().NextBytes(this.newNonce);
      FactorizedPair factorizedPair = Factorizator.Factorize(pq);
      using (MemoryStream output1 = new MemoryStream((int) byte.MaxValue))
      {
        byte[] array;
        using (BinaryWriter binaryWriter1 = new BinaryWriter((Stream) output1))
        {
          binaryWriter1.Write(2211011308U);
          Serializers.Bytes.write(binaryWriter1, pq.ToByteArrayUnsigned());
          Serializers.Bytes.write(binaryWriter1, factorizedPair.Min.ToByteArrayUnsigned());
          Serializers.Bytes.write(binaryWriter1, factorizedPair.Max.ToByteArrayUnsigned());
          binaryWriter1.Write(nonce);
          binaryWriter1.Write(serverNonce);
          binaryWriter1.Write(this.newNonce);
          byte[] data = (byte[]) null;
          byte[] buffer = (byte[]) null;
          foreach (byte[] fingerprint in fingerprints)
          {
            data = RSA.Encrypt(BitConverter.ToString(fingerprint).Replace("-", string.Empty), output1.GetBuffer(), 0, (int) output1.Position);
            if (data != null)
            {
              buffer = fingerprint;
              break;
            }
          }
          if (data == null)
            throw new InvalidOperationException(string.Format("not found valid key for fingerprints: {0}", (object) string.Join<byte[]>(", ", (IEnumerable<byte[]>) fingerprints)));
          using (MemoryStream output2 = new MemoryStream(1024))
          {
            using (BinaryWriter binaryWriter2 = new BinaryWriter((Stream) output2))
            {
              binaryWriter2.Write(3608339646U);
              binaryWriter2.Write(nonce);
              binaryWriter2.Write(serverNonce);
              Serializers.Bytes.write(binaryWriter2, factorizedPair.Min.ToByteArrayUnsigned());
              Serializers.Bytes.write(binaryWriter2, factorizedPair.Max.ToByteArrayUnsigned());
              binaryWriter2.Write(buffer);
              Serializers.Bytes.write(binaryWriter2, data);
              array = output2.ToArray();
            }
          }
        }
        return array;
      }
    }

    public Step2_Response FromBytes(byte[] response)
    {
      using (MemoryStream input = new MemoryStream(response, false))
      {
        using (BinaryReader binaryReader = new BinaryReader((Stream) input))
        {
          uint num = binaryReader.ReadUInt32();
          switch (num)
          {
            case 2043348061:
              throw new InvalidOperationException("server_DH_params_fail: TODO");
            case 3504867164:
              byte[] numArray1 = binaryReader.ReadBytes(16);
              byte[] numArray2 = binaryReader.ReadBytes(16);
              byte[] numArray3 = Serializers.Bytes.read(binaryReader);
              return new Step2_Response()
              {
                EncryptedAnswer = numArray3,
                ServerNonce = numArray2,
                Nonce = numArray1,
                NewNonce = this.newNonce
              };
            default:
              throw new InvalidOperationException(string.Format("invalid response code: {0}", (object) num));
          }
        }
      }
    }
  }
}
