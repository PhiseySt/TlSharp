using System;
using System.IO;
using System.Security.Cryptography;

namespace Abdt.Babdt.TlSharp.MTProto.Crypto
{
  public class AES
  {
    public static byte[] DecryptWithNonces(byte[] data, byte[] serverNonce, byte[] newNonce)
    {
      using (SHA1 shA1 = (SHA1) new SHA1Managed())
      {
        byte[] buffer1 = new byte[48];
        newNonce.CopyTo((Array) buffer1, 0);
        serverNonce.CopyTo((Array) buffer1, 32);
        byte[] hash1 = shA1.ComputeHash(buffer1);
        serverNonce.CopyTo((Array) buffer1, 0);
        newNonce.CopyTo((Array) buffer1, 16);
        byte[] hash2 = shA1.ComputeHash(buffer1);
        byte[] buffer2 = new byte[64];
        newNonce.CopyTo((Array) buffer2, 0);
        newNonce.CopyTo((Array) buffer2, 32);
        byte[] hash3 = shA1.ComputeHash(buffer2);
        using (MemoryStream memoryStream1 = new MemoryStream(32))
        {
          using (MemoryStream memoryStream2 = new MemoryStream(32))
          {
            memoryStream1.Write(hash1, 0, hash1.Length);
            memoryStream1.Write(hash2, 0, 12);
            memoryStream2.Write(hash2, 12, 8);
            memoryStream2.Write(hash3, 0, hash3.Length);
            memoryStream2.Write(newNonce, 0, 4);
            return AES.DecryptIGE(data, memoryStream1.ToArray(), memoryStream2.ToArray());
          }
        }
      }
    }

    public static AESKeyData GenerateKeyDataFromNonces(
      byte[] serverNonce,
      byte[] newNonce)
    {
      using (SHA1 shA1 = (SHA1) new SHA1Managed())
      {
        byte[] buffer1 = new byte[48];
        newNonce.CopyTo((Array) buffer1, 0);
        serverNonce.CopyTo((Array) buffer1, 32);
        byte[] hash1 = shA1.ComputeHash(buffer1);
        serverNonce.CopyTo((Array) buffer1, 0);
        newNonce.CopyTo((Array) buffer1, 16);
        byte[] hash2 = shA1.ComputeHash(buffer1);
        byte[] buffer2 = new byte[64];
        newNonce.CopyTo((Array) buffer2, 0);
        newNonce.CopyTo((Array) buffer2, 32);
        byte[] hash3 = shA1.ComputeHash(buffer2);
        using (MemoryStream memoryStream1 = new MemoryStream(32))
        {
          using (MemoryStream memoryStream2 = new MemoryStream(32))
          {
            memoryStream1.Write(hash1, 0, hash1.Length);
            memoryStream1.Write(hash2, 0, 12);
            memoryStream2.Write(hash2, 12, 8);
            memoryStream2.Write(hash3, 0, hash3.Length);
            memoryStream2.Write(newNonce, 0, 4);
            return new AESKeyData(memoryStream1.ToArray(), memoryStream2.ToArray());
          }
        }
      }
    }

    public static byte[] DecryptAES(AESKeyData key, byte[] ciphertext) => AES.DecryptIGE(ciphertext, key.Key, key.Iv);

    public static byte[] EncryptAES(AESKeyData key, byte[] plaintext) => AES.EncryptIGE(plaintext, key.Key, key.Iv);

    public static byte[] DecryptIGE(byte[] ciphertext, byte[] key, byte[] iv)
    {
      byte[] destinationArray1 = new byte[iv.Length / 2];
      byte[] destinationArray2 = new byte[iv.Length / 2];
      Array.Copy((Array) iv, 0, (Array) destinationArray1, 0, destinationArray1.Length);
      Array.Copy((Array) iv, destinationArray1.Length, (Array) destinationArray2, 0, destinationArray2.Length);
      AesEngine aesEngine = new AesEngine();
      aesEngine.Init(false, key);
      byte[] destinationArray3 = new byte[ciphertext.Length];
      int num = ciphertext.Length / 16;
      byte[] input = new byte[16];
      byte[] numArray = new byte[16];
      for (int index1 = 0; index1 < num; ++index1)
      {
        for (int index2 = 0; index2 < 16; ++index2)
          input[index2] = (byte) ((uint) ciphertext[index1 * 16 + index2] ^ (uint) destinationArray2[index2]);
        aesEngine.ProcessBlock(input, 0, numArray, 0);
        for (int index3 = 0; index3 < 16; ++index3)
          numArray[index3] ^= destinationArray1[index3];
        Array.Copy((Array) ciphertext, index1 * 16, (Array) destinationArray1, 0, 16);
        Array.Copy((Array) numArray, 0, (Array) destinationArray2, 0, 16);
        Array.Copy((Array) numArray, 0, (Array) destinationArray3, index1 * 16, 16);
      }
      return destinationArray3;
    }

    public static byte[] EncryptIGE(byte[] originPlaintext, byte[] key, byte[] iv)
    {
      byte[] array;
      using (MemoryStream memoryStream = new MemoryStream(originPlaintext.Length + 40))
      {
        memoryStream.Write(originPlaintext, 0, originPlaintext.Length);
        while (memoryStream.Position % 16L != 0L)
          memoryStream.WriteByte((byte) 0);
        array = memoryStream.ToArray();
      }
      byte[] destinationArray1 = new byte[iv.Length / 2];
      byte[] destinationArray2 = new byte[iv.Length / 2];
      Array.Copy((Array) iv, 0, (Array) destinationArray1, 0, destinationArray1.Length);
      Array.Copy((Array) iv, destinationArray1.Length, (Array) destinationArray2, 0, destinationArray2.Length);
      AesEngine aesEngine = new AesEngine();
      aesEngine.Init(true, key);
      int num = array.Length / 16;
      byte[] destinationArray3 = new byte[array.Length];
      byte[] numArray1 = new byte[16];
      byte[] numArray2 = new byte[16];
      for (int index1 = 0; index1 < num; ++index1)
      {
        Array.Copy((Array) array, 16 * index1, (Array) numArray2, 0, 16);
        for (int index2 = 0; index2 < 16; ++index2)
          numArray2[index2] ^= destinationArray1[index2];
        aesEngine.ProcessBlock(numArray2, 0, numArray1, 0);
        for (int index3 = 0; index3 < 16; ++index3)
          numArray1[index3] ^= destinationArray2[index3];
        Array.Copy((Array) numArray1, 0, (Array) destinationArray1, 0, 16);
        Array.Copy((Array) array, 16 * index1, (Array) destinationArray2, 0, 16);
        Array.Copy((Array) numArray1, 0, (Array) destinationArray3, index1 * 16, 16);
      }
      return destinationArray3;
    }

    public static byte[] XOR(byte[] buffer1, byte[] buffer2)
    {
      byte[] numArray = new byte[buffer1.Length];
      for (int index = 0; index < buffer1.Length; ++index)
        numArray[index] = (byte) ((uint) buffer1[index] ^ (uint) buffer2[index]);
      return numArray;
    }
  }
}
