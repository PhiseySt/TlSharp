using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Abdt.Babdt.TlSharp.MTProto;
using Abdt.Babdt.TlSharp.MTProto.Crypto;

namespace Abdt.Babdt.TlSharp.Auth
{
  public class Step3_CompleteDHExchange
  {
    private BigInteger _gab;
    private byte[] newNonce;
    private int timeOffset;

    public byte[] ToBytes(
      byte[] nonce,
      byte[] serverNonce,
      byte[] newNonce,
      byte[] encryptedAnswer)
    {
      this.newNonce = newNonce;
      AESKeyData keyDataFromNonces = AES.GenerateKeyDataFromNonces(serverNonce, newNonce);
      int num1;
      BigInteger m;
      BigInteger bigInteger1;
      using (MemoryStream input = new MemoryStream(AES.DecryptAES(keyDataFromNonces, encryptedAnswer)))
      {
        using (BinaryReader binaryReader = new BinaryReader((Stream) input))
        {
          binaryReader.ReadBytes(20);
          uint num2 = binaryReader.ReadUInt32();
          if (num2 != 3045658042U)
            throw new InvalidOperationException(string.Format("invalid dh_inner_data code: {0}", (object) num2));
          if (!((IEnumerable<byte>) binaryReader.ReadBytes(16)).SequenceEqual<byte>((IEnumerable<byte>) nonce))
            throw new InvalidOperationException("invalid nonce in encrypted answer");
          num1 = ((IEnumerable<byte>) binaryReader.ReadBytes(16)).SequenceEqual<byte>((IEnumerable<byte>) serverNonce) ? binaryReader.ReadInt32() : throw new InvalidOperationException("invalid server nonce in encrypted answer");
          m = new BigInteger(1, Serializers.Bytes.read(binaryReader));
          bigInteger1 = new BigInteger(1, Serializers.Bytes.read(binaryReader));
          this.timeOffset = binaryReader.ReadInt32() - (int) (Convert.ToInt64((DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalMilliseconds) / 1000L);
        }
      }
      BigInteger exponent = new BigInteger(2048, new Random());
      BigInteger bigInteger2 = BigInteger.ValueOf((long) num1).ModPow(exponent, m);
      this._gab = bigInteger1.ModPow(exponent, m);
      byte[] array;
      using (MemoryStream output1 = new MemoryStream())
      {
        using (BinaryWriter binaryWriter1 = new BinaryWriter((Stream) output1))
        {
          binaryWriter1.Write(1715713620);
          binaryWriter1.Write(nonce);
          binaryWriter1.Write(serverNonce);
          binaryWriter1.Write(0L);
          Serializers.Bytes.write(binaryWriter1, bigInteger2.ToByteArrayUnsigned());
          using (MemoryStream output2 = new MemoryStream())
          {
            using (BinaryWriter binaryWriter2 = new BinaryWriter((Stream) output2))
            {
              using (SHA1 shA1 = (SHA1) new SHA1Managed())
              {
                binaryWriter2.Write(shA1.ComputeHash(output1.GetBuffer(), 0, (int) output1.Position));
                binaryWriter2.Write(output1.GetBuffer(), 0, (int) output1.Position);
                array = output2.ToArray();
              }
            }
          }
        }
      }
      byte[] data = AES.EncryptAES(keyDataFromNonces, array);
      using (MemoryStream output = new MemoryStream())
      {
        using (BinaryWriter binaryWriter = new BinaryWriter((Stream) output))
        {
          binaryWriter.Write(4110704415U);
          binaryWriter.Write(nonce);
          binaryWriter.Write(serverNonce);
          Serializers.Bytes.write(binaryWriter, data);
          return output.ToArray();
        }
      }
    }

    public Step3_Response FromBytes(byte[] response)
    {
      using (MemoryStream input = new MemoryStream(response))
      {
        using (BinaryReader binaryReader = new BinaryReader((Stream) input))
        {
          uint num = binaryReader.ReadUInt32();
          switch (num)
          {
            case 1003222836:
              binaryReader.ReadBytes(16);
              binaryReader.ReadBytes(16);
              byte[] first = binaryReader.ReadBytes(16);
              AuthKey authKey = new AuthKey(this._gab);
              byte[] second = authKey.CalcNewNonceHash(this.newNonce, 1);
              if (!((IEnumerable<byte>) first).SequenceEqual<byte>((IEnumerable<byte>) second))
                throw new InvalidOperationException("invalid new nonce hash");
              return new Step3_Response()
              {
                AuthKey = authKey,
                TimeOffset = this.timeOffset
              };
            case 1188831161:
              throw new NotImplementedException("dh_gen_retry");
            case 2795351554:
              throw new NotImplementedException("dh_gen_fail");
            default:
              throw new InvalidOperationException(string.Format("dh_gen unknown: {0}", (object) num));
          }
        }
      }
    }
  }
}
