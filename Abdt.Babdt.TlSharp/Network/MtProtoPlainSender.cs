using System;
using System.IO;
using System.Threading.Tasks;

namespace Abdt.Babdt.TlSharp.Network
{
  public class MtProtoPlainSender
  {
    private int timeOffset;
    private long lastMessageId;
    private Random random;
    private TcpTransport _transport;

    public MtProtoPlainSender(TcpTransport transport)
    {
      this._transport = transport;
      this.random = new Random();
    }

    public async Task Send(byte[] data)
    {
      using (MemoryStream memoryStream = new MemoryStream())
      {
        using (BinaryWriter binaryWriter = new BinaryWriter((Stream) memoryStream))
        {
          binaryWriter.Write(0L);
          binaryWriter.Write(this.GetNewMessageId());
          binaryWriter.Write(data.Length);
          binaryWriter.Write(data);
          await this._transport.Send(memoryStream.ToArray());
        }
      }
    }

    public async Task<byte[]> Receive()
    {
      byte[] numArray;
      using (MemoryStream input = new MemoryStream((await this._transport.Receieve()).Body))
      {
        using (BinaryReader binaryReader = new BinaryReader((Stream) input))
        {
          binaryReader.ReadInt64();
          binaryReader.ReadInt64();
          int count = binaryReader.ReadInt32();
          numArray = binaryReader.ReadBytes(count);
        }
      }
      return numArray;
    }

    private long GetNewMessageId()
    {
      long int64 = Convert.ToInt64((DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalMilliseconds);
      long newMessageId = int64 / 1000L + (long) this.timeOffset << 32 | int64 % 1000L << 22 | (long) (this.random.Next(524288) << 2);
      if (this.lastMessageId >= newMessageId)
        newMessageId = this.lastMessageId + 4L;
      this.lastMessageId = newMessageId;
      return newMessageId;
    }
  }
}
