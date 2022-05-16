using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Abdt.Babdt.TlSharp.MTProto
{
  public class Serializers
  {
    public static string VectorToString<T>(List<T> list)
    {
      string[] strArray = new string[list.Count];
      for (int index = 0; index < list.Count; ++index)
        strArray[index] = list[index].ToString();
      return "[" + string.Join(", ", strArray) + "]";
    }

    public static class Bytes
    {
      public static byte[] read(BinaryReader binaryReader)
      {
        byte num1 = binaryReader.ReadByte();
        int count1;
        int num2;
        if (num1 == (byte) 254)
        {
          count1 = (int) binaryReader.ReadByte() | (int) binaryReader.ReadByte() << 8 | (int) binaryReader.ReadByte() << 16;
          num2 = count1 % 4;
        }
        else
        {
          count1 = (int) num1;
          num2 = (count1 + 1) % 4;
        }
        byte[] numArray = binaryReader.ReadBytes(count1);
        if (num2 <= 0)
          return numArray;
        int count2 = 4 - num2;
        binaryReader.ReadBytes(count2);
        return numArray;
      }

      public static BinaryWriter write(BinaryWriter binaryWriter, byte[] data)
      {
        int num;
        if (data.Length < 254)
        {
          num = (data.Length + 1) % 4;
          if (num != 0)
            num = 4 - num;
          binaryWriter.Write((byte) data.Length);
          binaryWriter.Write(data);
        }
        else
        {
          num = data.Length % 4;
          if (num != 0)
            num = 4 - num;
          binaryWriter.Write((byte) 254);
          binaryWriter.Write((byte) data.Length);
          binaryWriter.Write((byte) (data.Length >> 8));
          binaryWriter.Write((byte) (data.Length >> 16));
          binaryWriter.Write(data);
        }
        for (int index = 0; index < num; ++index)
          binaryWriter.Write((byte) 0);
        return binaryWriter;
      }
    }

    public static class String
    {
      public static string read(BinaryReader reader)
      {
        byte[] bytes = Serializers.Bytes.read(reader);
        return Encoding.UTF8.GetString(bytes, 0, bytes.Length);
      }

      public static BinaryWriter write(BinaryWriter writer, string str) => Serializers.Bytes.write(writer, Encoding.UTF8.GetBytes(str));
    }
  }
}
