using System;
using System.Security.Cryptography;
using Abdt.Babdt.TlSharp.MTProto.Crypto;

namespace Abdt.Babdt.TlSharp.Utils
{
  public class Helpers
  {
    private static Random random = new Random();

    public static ulong GenerateRandomUlong() => (ulong) Helpers.random.Next() << 32 | (ulong) Helpers.random.Next();

    public static long GenerateRandomLong() => (long) Helpers.random.Next() << 32 | (long) Helpers.random.Next();

    public static byte[] GenerateRandomBytes(int num)
    {
      byte[] buffer = new byte[num];
      Helpers.random.NextBytes(buffer);
      return buffer;
    }

    public static AESKeyData CalcKey(byte[] sharedKey, byte[] msgKey, bool client)
    {
      int sourceIndex = client ? 0 : 8;
      byte[] numArray1 = new byte[48];
      Array.Copy((Array) msgKey, 0, (Array) numArray1, 0, 16);
      Array.Copy((Array) sharedKey, sourceIndex, (Array) numArray1, 16, 32);
      byte[] sourceArray1 = Helpers.sha1(numArray1);
      Array.Copy((Array) sharedKey, 32 + sourceIndex, (Array) numArray1, 0, 16);
      Array.Copy((Array) msgKey, 0, (Array) numArray1, 16, 16);
      Array.Copy((Array) sharedKey, 48 + sourceIndex, (Array) numArray1, 32, 16);
      byte[] sourceArray2 = Helpers.sha1(numArray1);
      Array.Copy((Array) sharedKey, 64 + sourceIndex, (Array) numArray1, 0, 32);
      Array.Copy((Array) msgKey, 0, (Array) numArray1, 32, 16);
      byte[] sourceArray3 = Helpers.sha1(numArray1);
      Array.Copy((Array) msgKey, 0, (Array) numArray1, 0, 16);
      Array.Copy((Array) sharedKey, 96 + sourceIndex, (Array) numArray1, 16, 32);
      byte[] sourceArray4 = Helpers.sha1(numArray1);
      byte[] numArray2 = new byte[32];
      Array.Copy((Array) sourceArray1, 0, (Array) numArray2, 0, 8);
      Array.Copy((Array) sourceArray2, 8, (Array) numArray2, 8, 12);
      Array.Copy((Array) sourceArray3, 4, (Array) numArray2, 20, 12);
      byte[] numArray3 = new byte[32];
      Array.Copy((Array) sourceArray1, 8, (Array) numArray3, 0, 12);
      Array.Copy((Array) sourceArray2, 0, (Array) numArray3, 12, 8);
      Array.Copy((Array) sourceArray3, 16, (Array) numArray3, 20, 4);
      byte[] destinationArray = numArray3;
      Array.Copy((Array) sourceArray4, 0, (Array) destinationArray, 24, 8);
      return new AESKeyData(numArray2, numArray3);
    }

    public static byte[] CalcMsgKey(byte[] data)
    {
      byte[] destinationArray = new byte[16];
      Array.Copy((Array) Helpers.sha1(data), 4, (Array) destinationArray, 0, 16);
      return destinationArray;
    }

    public static byte[] CalcMsgKey(byte[] data, int offset, int limit)
    {
      byte[] destinationArray = new byte[16];
      Array.Copy((Array) Helpers.sha1(data, offset, limit), 4, (Array) destinationArray, 0, 16);
      return destinationArray;
    }

    public static byte[] sha1(byte[] data)
    {
      using (SHA1 shA1 = (SHA1) new SHA1Managed())
        return shA1.ComputeHash(data);
    }

    public static byte[] sha1(byte[] data, int offset, int limit)
    {
      using (SHA1 shA1 = (SHA1) new SHA1Managed())
        return shA1.ComputeHash(data, offset, limit);
    }
  }
}
