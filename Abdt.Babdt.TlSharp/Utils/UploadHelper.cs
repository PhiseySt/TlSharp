using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Abdt.Babdt.TlShema;
using Abdt.Babdt.TlShema.Upload;

namespace Abdt.Babdt.TlSharp.Utils
{
  public static class UploadHelper
  {
    private static string GetFileHash(byte[] data)
    {
      using (MD5 md5 = MD5.Create())
      {
        byte[] hash = md5.ComputeHash(data);
        StringBuilder stringBuilder = new StringBuilder(hash.Length * 2);
        foreach (byte num in hash)
          stringBuilder.Append(num.ToString("x2"));
        return stringBuilder.ToString();
      }
    }

    public static async Task<TLAbsInputFile> UploadFile(
      this TelegramClient client,
      string name,
      StreamReader reader)
    {
      return await UploadHelper.UploadFile(name, reader, client, reader.BaseStream.Length >= 10485760L);
    }

    private static byte[] GetFile(StreamReader reader)
    {
      byte[] buffer = new byte[reader.BaseStream.Length];
      using (reader)
        reader.BaseStream.Read(buffer, 0, (int) reader.BaseStream.Length);
      return buffer;
    }

    private static Queue<byte[]> GetFileParts(byte[] file)
    {
      Queue<byte[]> fileParts = new Queue<byte[]>();
      using (MemoryStream memoryStream = new MemoryStream(file))
      {
        while (memoryStream.Position != memoryStream.Length)
        {
          if (memoryStream.Length - memoryStream.Position > 524288L)
          {
            byte[] buffer = new byte[524288];
            memoryStream.Read(buffer, 0, 524288);
            fileParts.Enqueue(buffer);
          }
          else
          {
            long count = memoryStream.Length - memoryStream.Position;
            byte[] buffer = new byte[count];
            memoryStream.Read(buffer, 0, (int) count);
            fileParts.Enqueue(buffer);
          }
        }
      }
      return fileParts;
    }

    private static async Task<TLAbsInputFile> UploadFile(
      string name,
      StreamReader reader,
      TelegramClient client,
      bool isBigFileUpload)
    {
      byte[] file = UploadHelper.GetFile(reader);
      Queue<byte[]> fileParts = UploadHelper.GetFileParts(file);
      int partNumber = 0;
      int partsCount = fileParts.Count;
      long file_id = BitConverter.ToInt64(Helpers.GenerateRandomBytes(8), 0);
      while (fileParts.Count != 0)
      {
        byte[] numArray = fileParts.Dequeue();
        if (isBigFileUpload)
        {
          int num1 = await client.SendRequestAsync<bool>((TLMethod) new TLRequestSaveBigFilePart()
          {
            FileId = file_id,
            FilePart = partNumber,
            Bytes = numArray,
            FileTotalParts = partsCount
          }) ? 1 : 0;
        }
        else
        {
          int num2 = await client.SendRequestAsync<bool>((TLMethod) new TLRequestSaveFilePart()
          {
            FileId = file_id,
            FilePart = partNumber,
            Bytes = numArray
          }) ? 1 : 0;
        }
        ++partNumber;
      }
      if (isBigFileUpload)
        return (TLAbsInputFile) new TLInputFileBig()
        {
          Id = file_id,
          Name = name,
          Parts = partsCount
        };
      return (TLAbsInputFile) new TLInputFile()
      {
        Id = file_id,
        Name = name,
        Parts = partsCount,
        Md5Checksum = UploadHelper.GetFileHash(file)
      };
    }
  }
}
