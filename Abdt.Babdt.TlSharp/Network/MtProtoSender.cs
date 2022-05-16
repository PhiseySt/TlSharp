using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Abdt.Babdt.TlSharp.MTProto;
using Abdt.Babdt.TlSharp.MTProto.Crypto;
using Abdt.Babdt.TlSharp.Requests;
using Abdt.Babdt.TlSharp.Utils;
using Abdt.Babdt.TlShema;

namespace Abdt.Babdt.TlSharp.Network
{
  public class MtProtoSender
  {
    private readonly TcpTransport _transport;
    private readonly Session _session;
    public readonly List<ulong> needConfirmation = new List<ulong>();

    public MtProtoSender(TcpTransport transport, Session session)
    {
      this._transport = transport;
      this._session = session;
    }

    private int GenerateSequence(bool confirmed) => !confirmed ? this._session.Sequence * 2 : this._session.Sequence++ * 2 + 1;

    public async Task Send(TLMethod request)
    {
      MemoryStream memory;
      BinaryWriter writer;
      if (this.needConfirmation.Any<ulong>())
      {
        AckRequest request1 = new AckRequest(this.needConfirmation);
        memory = new MemoryStream();
        try
        {
          writer = new BinaryWriter((Stream) memory);
          try
          {
            request1.SerializeBody(writer);
            await this.Send(memory.ToArray(), (TLMethod) request1);
            this.needConfirmation.Clear();
          }
          finally
          {
            writer?.Dispose();
          }
          writer = (BinaryWriter) null;
        }
        finally
        {
          memory?.Dispose();
        }
        memory = (MemoryStream) null;
      }
      memory = new MemoryStream();
      try
      {
        writer = new BinaryWriter((Stream) memory);
        try
        {
          request.SerializeBody(writer);
          await this.Send(memory.ToArray(), request);
        }
        finally
        {
          writer?.Dispose();
        }
        writer = (BinaryWriter) null;
      }
      finally
      {
        memory?.Dispose();
      }
      memory = (MemoryStream) null;
      this._session.Save();
    }

    public async Task Send(byte[] packet, TLMethod request)
    {
      request.MessageId = this._session.GetNewMessageId();
      byte[] numArray;
      byte[] buffer;
      using (MemoryStream output = this.makeMemory(32 + packet.Length))
      {
        using (BinaryWriter binaryWriter = new BinaryWriter((Stream) output))
        {
          binaryWriter.Write(this._session.Salt);
          binaryWriter.Write(this._session.Id);
          binaryWriter.Write(request.MessageId);
          binaryWriter.Write(this.GenerateSequence(request.Confirmed));
          binaryWriter.Write(packet.Length);
          binaryWriter.Write(packet);
          numArray = Helpers.CalcMsgKey(output.GetBuffer());
          buffer = AES.EncryptAES(Helpers.CalcKey(this._session.AuthKey.Data, numArray, true), output.GetBuffer());
        }
      }
      using (MemoryStream ciphertextPacket = this.makeMemory(24 + buffer.Length))
      {
        using (BinaryWriter writer = new BinaryWriter((Stream) ciphertextPacket))
        {
          writer.Write(this._session.AuthKey.Id);
          writer.Write(numArray);
          writer.Write(buffer);
          await this._transport.Send(ciphertextPacket.GetBuffer());
        }
      }
    }

    private Tuple<byte[], ulong, int> DecodeMessage(byte[] body)
    {
      ulong num1;
      int num2;
      byte[] numArray;
      using (MemoryStream input1 = new MemoryStream(body))
      {
        using (BinaryReader binaryReader1 = new BinaryReader((Stream) input1))
        {
          if (binaryReader1.BaseStream.Length < 8L)
            throw new InvalidOperationException("Can't decode packet");
          long num3 = (long) binaryReader1.ReadUInt64();
          using (MemoryStream input2 = new MemoryStream(AES.DecryptAES(Helpers.CalcKey(this._session.AuthKey.Data, binaryReader1.ReadBytes(16), false), binaryReader1.ReadBytes((int) (input1.Length - input1.Position)))))
          {
            using (BinaryReader binaryReader2 = new BinaryReader((Stream) input2))
            {
              long num4 = (long) binaryReader2.ReadUInt64();
              long num5 = (long) binaryReader2.ReadUInt64();
              num1 = binaryReader2.ReadUInt64();
              num2 = binaryReader2.ReadInt32();
              int count = binaryReader2.ReadInt32();
              numArray = binaryReader2.ReadBytes(count);
            }
          }
        }
      }
      return new Tuple<byte[], ulong, int>(numArray, num1, num2);
    }

    public async Task<byte[]> Receive(TLMethod request)
    {
      while (!request.ConfirmReceived)
      {
        Tuple<byte[], ulong, int> tuple = this.DecodeMessage((await this._transport.Receieve()).Body);
        using (MemoryStream input = new MemoryStream(tuple.Item1, false))
        {
          using (BinaryReader messageReader = new BinaryReader((Stream) input))
            this.processMessage(tuple.Item2, tuple.Item3, messageReader, request);
        }
      }
      return (byte[]) null;
    }

    public async Task SendPingAsync()
    {
      PingRequest pingRequest = new PingRequest();
      using (MemoryStream memory = new MemoryStream())
      {
        using (BinaryWriter writer = new BinaryWriter((Stream) memory))
        {
          pingRequest.SerializeBody(writer);
          await this.Send(memory.ToArray(), (TLMethod) pingRequest);
        }
      }
      byte[] numArray = await this.Receive((TLMethod) pingRequest);
    }

    private bool processMessage(
      ulong messageId,
      int sequence,
      BinaryReader messageReader,
      TLMethod request)
    {
      this.needConfirmation.Add(messageId);
      uint num = messageReader.ReadUInt32();
      messageReader.BaseStream.Position -= 4L;
      switch (num)
      {
        case 661470918:
          return this.HandleMsgDetailedInfo(messageId, sequence, messageReader);
        case 724548942:
        case 1918567619:
        case 1957577280:
        case 2027216577:
        case 3556005764:
        case 3809980286:
          return this.HandleUpdate(messageId, sequence, messageReader);
        case 812830625:
          return this.HandleGzipPacked(messageId, sequence, messageReader, request);
        case 880243653:
          return this.HandlePong(messageId, sequence, messageReader, request);
        case 1658238041:
          return this.HandleMsgsAck(messageId, sequence, messageReader);
        case 1945237724:
          return this.HandleContainer(messageId, sequence, messageReader, request);
        case 2059302892:
          return this.HandlePing(messageId, sequence, messageReader);
        case 2663516424:
          return this.HandleNewSessionCreated(messageId, sequence, messageReader);
        case 2817521681:
          return this.HandleBadMsgNotification(messageId, sequence, messageReader);
        case 2924480661:
          return this.HandleFutureSalts(messageId, sequence, messageReader);
        case 3987424379:
          return this.HandleBadServerSalt(messageId, sequence, messageReader, request);
        case 4082920705:
          return this.HandleRpcResult(messageId, sequence, messageReader, request);
        default:
          return false;
      }
    }

    private bool HandleUpdate(ulong messageId, int sequence, BinaryReader messageReader) => false;

    private bool HandleGzipPacked(
      ulong messageId,
      int sequence,
      BinaryReader messageReader,
      TLMethod request)
    {
      int num = (int) messageReader.ReadUInt32();
      MemoryStream destination = new MemoryStream();
      using (GZipStream gzipStream = new GZipStream((Stream) new MemoryStream(Serializers.Bytes.read(messageReader)), CompressionMode.Decompress))
        gzipStream.CopyTo((Stream) destination);
      using (MemoryStream input = new MemoryStream(destination.ToArray(), false))
      {
        using (BinaryReader messageReader1 = new BinaryReader((Stream) input))
          this.processMessage(messageId, sequence, messageReader1, request);
      }
      return true;
    }

    private bool HandleRpcResult(
      ulong messageId,
      int sequence,
      BinaryReader messageReader,
      TLMethod request)
    {
      int num = (int) messageReader.ReadUInt32();
      if ((long) messageReader.ReadUInt64() == request.MessageId)
        request.ConfirmReceived = true;
      switch (messageReader.ReadUInt32())
      {
        case 558156313:
          messageReader.ReadInt32();
          string str = Serializers.String.read(messageReader);
          if (str.StartsWith("FLOOD_WAIT_"))
            throw new FloodException(TimeSpan.FromSeconds((double) int.Parse(Regex.Match(str, "\\d+").Value)));
          if (str.StartsWith("PHONE_MIGRATE_"))
            throw new PhoneMigrationException(int.Parse(Regex.Match(str, "\\d+").Value));
          if (str.StartsWith("FILE_MIGRATE_"))
            throw new FileMigrationException(int.Parse(Regex.Match(str, "\\d+").Value));
          if (str.StartsWith("USER_MIGRATE_"))
            throw new UserMigrationException(int.Parse(Regex.Match(str, "\\d+").Value));
          if (str.StartsWith("NETWORK_MIGRATE_"))
            throw new NetworkMigrationException(int.Parse(Regex.Match(str, "\\d+").Value));
          if (str == "PHONE_CODE_INVALID")
            throw new InvalidPhoneCodeException("The numeric code used to authenticate does not match the numeric code sent by SMS/Telegram");
          if (str == "SESSION_PASSWORD_NEEDED")
            throw new CloudPasswordNeededException("This Account has Cloud Password !");
          throw new InvalidOperationException(str);
        case 812830625:
          try
          {
            byte[] buffer = Serializers.Bytes.read(messageReader);
            using (MemoryStream memoryStream1 = new MemoryStream())
            {
              using (MemoryStream memoryStream2 = new MemoryStream(buffer, false))
              {
                using (GZipStream gzipStream = new GZipStream((Stream) memoryStream2, CompressionMode.Decompress))
                {
                  gzipStream.CopyTo((Stream) memoryStream1);
                  memoryStream1.Position = 0L;
                }
              }
              using (BinaryReader stream = new BinaryReader((Stream) memoryStream1))
              {
                request.DeserializeResponse(stream);
                break;
              }
            }
          }
          catch (Exception ex)
          {
            break;
          }
        default:
          messageReader.BaseStream.Position -= 4L;
          request.DeserializeResponse(messageReader);
          break;
      }
      return false;
    }

    private bool HandleMsgDetailedInfo(ulong messageId, int sequence, BinaryReader messageReader) => false;

    private bool HandleBadMsgNotification(
      ulong messageId,
      int sequence,
      BinaryReader messageReader)
    {
      int num1 = (int) messageReader.ReadUInt32();
      long num2 = (long) messageReader.ReadUInt64();
      messageReader.ReadInt32();
      switch (messageReader.ReadInt32())
      {
        case 16:
          throw new InvalidOperationException("msg_id too low (most likely, client time is wrong; it would be worthwhile to synchronize it using msg_id notifications and re-send the original message with the “correct” msg_id or wrap it in a container with a new msg_id if the original message had waited too long on the client to be transmitted)");
        case 17:
          throw new InvalidOperationException("msg_id too high (similar to the previous case, the client time has to be synchronized, and the message re-sent with the correct msg_id)");
        case 18:
          throw new InvalidOperationException("incorrect two lower order msg_id bits (the server expects client message msg_id to be divisible by 4)");
        case 19:
          throw new InvalidOperationException("container msg_id is the same as msg_id of a previously received message (this must never happen)");
        case 20:
          throw new InvalidOperationException("message too old, and it cannot be verified whether the server has received a message with this msg_id or not");
        case 32:
          throw new InvalidOperationException("msg_seqno too low (the server has already received a message with a lower msg_id but with either a higher or an equal and odd seqno)");
        case 33:
          throw new InvalidOperationException(" msg_seqno too high (similarly, there is a message with a higher msg_id but with either a lower or an equal and odd seqno)");
        case 34:
          throw new InvalidOperationException("an even msg_seqno expected (irrelevant message), but odd received");
        case 35:
          throw new InvalidOperationException("odd msg_seqno expected (relevant message), but even received");
        case 48:
          throw new InvalidOperationException("incorrect server salt (in this case, the bad_server_salt response is received with the correct salt, and the message is to be re-sent with it)");
        case 64:
          throw new InvalidOperationException("invalid container");
        default:
          throw new NotImplementedException("This should never happens");
      }
    }

    private bool HandleBadServerSalt(
      ulong messageId,
      int sequence,
      BinaryReader messageReader,
      TLMethod request)
    {
      int num1 = (int) messageReader.ReadUInt32();
      long num2 = (long) messageReader.ReadUInt64();
      messageReader.ReadInt32();
      messageReader.ReadInt32();
      this._session.Salt = messageReader.ReadUInt64();
      this.Send(request);
      return true;
    }

    private bool HandleMsgsAck(ulong messageId, int sequence, BinaryReader messageReader) => false;

    private bool HandleNewSessionCreated(ulong messageId, int sequence, BinaryReader messageReader) => false;

    private bool HandleFutureSalts(ulong messageId, int sequence, BinaryReader messageReader)
    {
      int num1 = (int) messageReader.ReadUInt32();
      long num2 = (long) messageReader.ReadUInt64();
      messageReader.BaseStream.Position -= 12L;
      throw new NotImplementedException("Handle future server salts function isn't implemented.");
    }

    private bool HandlePong(
      ulong messageId,
      int sequence,
      BinaryReader messageReader,
      TLMethod request)
    {
      int num = (int) messageReader.ReadUInt32();
      if ((long) messageReader.ReadUInt64() == request.MessageId)
        request.ConfirmReceived = true;
      return false;
    }

    private bool HandlePing(ulong messageId, int sequence, BinaryReader messageReader) => false;

    private bool HandleContainer(
      ulong messageId,
      int sequence,
      BinaryReader messageReader,
      TLMethod request)
    {
      int num1 = (int) messageReader.ReadUInt32();
      int num2 = messageReader.ReadInt32();
      for (int index = 0; index < num2; ++index)
      {
        ulong messageId1 = messageReader.ReadUInt64();
        messageReader.ReadInt32();
        int num3 = messageReader.ReadInt32();
        long position = messageReader.BaseStream.Position;
        try
        {
          if (!this.processMessage(messageId1, sequence, messageReader, request))
            messageReader.BaseStream.Position = position + (long) num3;
        }
        catch (Exception ex)
        {
          messageReader.BaseStream.Position = position + (long) num3;
        }
      }
      return false;
    }

    private MemoryStream makeMemory(int len) => new MemoryStream(new byte[len], 0, len, true, true);
  }
}
