using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Abdt.Babdt.TlSharp.Network
{
  public class TcpTransport : IDisposable
  {
    private readonly TcpClient _tcpClient;
    private int sendCounter;

    public TcpTransport(string address, int port, TcpClientConnectionHandler handler = null)
    {
      if (handler == null)
      {
        this._tcpClient = new TcpClient();
        this._tcpClient.Connect(IPAddress.Parse(address), port);
      }
      else
        this._tcpClient = handler(address, port);
    }

    public async Task Send(byte[] packet)
    {
      if (!this._tcpClient.Connected)
        throw new InvalidOperationException("Client not connected to server.");
      TcpMessage tcpMessage = new TcpMessage(this.sendCounter, packet);
      await this._tcpClient.GetStream().WriteAsync(tcpMessage.Encode(), 0, tcpMessage.Encode().Length);
      ++this.sendCounter;
    }

    public async Task<TcpMessage> Receieve()
    {
      NetworkStream stream = this._tcpClient.GetStream();
      byte[] packetLengthBytes = new byte[4];
      int packetLength = await stream.ReadAsync(packetLengthBytes, 0, 4) == 4 ? BitConverter.ToInt32(packetLengthBytes, 0) : throw new InvalidOperationException("Couldn't read the packet length");
      byte[] seqBytes = new byte[4];
      int seq = await stream.ReadAsync(seqBytes, 0, 4) == 4 ? BitConverter.ToInt32(seqBytes, 0) : throw new InvalidOperationException("Couldn't read the sequence");
      int readBytes = 0;
      byte[] body = new byte[packetLength - 12];
      int neededToRead = packetLength - 12;
      do
      {
        byte[] bodyByte = new byte[packetLength - 12];
        int count = await stream.ReadAsync(bodyByte, 0, neededToRead);
        neededToRead -= count;
        Buffer.BlockCopy((Array) bodyByte, 0, (Array) body, readBytes, count);
        readBytes += count;
        bodyByte = (byte[]) null;
      }
      while (readBytes != packetLength - 12);
      byte[] crcBytes = new byte[4];
      int num = await stream.ReadAsync(crcBytes, 0, 4) == 4 ? BitConverter.ToInt32(crcBytes, 0) : throw new InvalidOperationException("Couldn't read the crc");
      byte[] numArray = new byte[packetLengthBytes.Length + seqBytes.Length + body.Length];
      Buffer.BlockCopy((Array) packetLengthBytes, 0, (Array) numArray, 0, packetLengthBytes.Length);
      Buffer.BlockCopy((Array) seqBytes, 0, (Array) numArray, packetLengthBytes.Length, seqBytes.Length);
      Buffer.BlockCopy((Array) body, 0, (Array) numArray, packetLengthBytes.Length + seqBytes.Length, body.Length);
      CRC32 crC32 = new CRC32();
      crC32.SlurpBlock(numArray, 0, numArray.Length);
      int crc32Result = crC32.Crc32Result;
      if (num != crc32Result)
        throw new InvalidOperationException("invalid checksum! skip");
      return new TcpMessage(seq, body);
    }

    public bool IsConnected => this._tcpClient.Connected;

    public void Dispose()
    {
      if (!this._tcpClient.Connected)
        return;
      this._tcpClient.Close();
    }
  }
}
