using System;
using System.IO;

namespace Abdt.Babdt.TlSharp.Network
{
  public class TcpMessage
  {
    public int SequneceNumber { get; private set; }

    public byte[] Body { get; private set; }

    public TcpMessage(int seqNumber, byte[] body)
    {
      if (body == null)
        throw new ArgumentNullException(nameof (body));
      this.SequneceNumber = seqNumber;
      this.Body = body;
    }

    public byte[] Encode()
    {
      using (MemoryStream output = new MemoryStream())
      {
        using (BinaryWriter binaryWriter = new BinaryWriter((Stream) output))
        {
          binaryWriter.Write(this.Body.Length + 12);
          binaryWriter.Write(this.SequneceNumber);
          binaryWriter.Write(this.Body);
          CRC32 crC32 = new CRC32();
          crC32.SlurpBlock(output.GetBuffer(), 0, 8 + this.Body.Length);
          binaryWriter.Write(crC32.Crc32Result);
          return output.ToArray();
        }
      }
    }

    public static TcpMessage Decode(byte[] body)
    {
      if (body == null)
        throw new ArgumentNullException(nameof (body));
      if (body.Length < 12)
        throw new InvalidOperationException("Ops, wrong size of input packet");
      using (MemoryStream input = new MemoryStream(body))
      {
        using (BinaryReader binaryReader = new BinaryReader((Stream) input))
        {
          int num1 = binaryReader.ReadInt32();
          if (num1 < 12)
            throw new InvalidOperationException(string.Format("invalid packet length: {0}", (object) num1));
          int seqNumber = binaryReader.ReadInt32();
          byte[] numArray = binaryReader.ReadBytes(num1 - 12);
          int num2 = binaryReader.ReadInt32();
          CRC32 crC32 = new CRC32();
          crC32.SlurpBlock(body, 0, num1 - 4);
          int crc32Result = crC32.Crc32Result;
          if (num2 != crc32Result)
            throw new InvalidOperationException("invalid checksum! skip");
          byte[] body1 = numArray;
          return new TcpMessage(seqNumber, body1);
        }
      }
    }
  }
}
