using System;
using System.IO;
using System.Security.Cryptography;

namespace Abdt.Babdt.TlSharp.MTProto.Crypto
{
  internal class RSAServerKey
  {
    private string fingerprint;
    private BigInteger m;
    private BigInteger e;

    public RSAServerKey(string fingerprint, BigInteger m, BigInteger e)
    {
      this.fingerprint = fingerprint;
      this.m = m;
      this.e = e;
    }

    public byte[] Encrypt(byte[] data, int offset, int length)
    {
      using (MemoryStream output = new MemoryStream((int) byte.MaxValue))
      {
        using (BinaryWriter binaryWriter = new BinaryWriter((Stream) output))
        {
          using (SHA1 shA1 = (SHA1) new SHA1Managed())
          {
            byte[] hash = shA1.ComputeHash(data, offset, length);
            binaryWriter.Write(hash);
          }
          output.Write(data, offset, length);
          if (length < 235)
          {
            byte[] buffer = new byte[235 - length];
            new Random().NextBytes(buffer);
            output.Write(buffer, 0, buffer.Length);
          }
          byte[] byteArrayUnsigned = new BigInteger(1, output.ToArray()).ModPow(this.e, this.m).ToByteArrayUnsigned();
          if (byteArrayUnsigned.Length == 256)
            return byteArrayUnsigned;
          byte[] numArray = new byte[256];
          int index1 = 256 - byteArrayUnsigned.Length;
          for (int index2 = 0; index2 < index1; ++index2)
            numArray[index2] = (byte) 0;
          byteArrayUnsigned.CopyTo((Array) numArray, index1);
          return numArray;
        }
      }
    }
  }
}
