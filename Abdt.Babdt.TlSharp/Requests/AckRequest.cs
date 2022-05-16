using System;
using System.Collections.Generic;
using System.IO;
using Abdt.Babdt.TlShema;

namespace Abdt.Babdt.TlSharp.Requests
{
  public class AckRequest : TLMethod
  {
    private readonly List<ulong> _msgs;

    public AckRequest(List<ulong> msgs) => this._msgs = msgs;

    public override void SerializeBody(BinaryWriter writer)
    {
      writer.Write(1658238041);
      writer.Write(481674261);
      writer.Write(this._msgs.Count);
      foreach (ulong msg in this._msgs)
        writer.Write(msg);
    }

    public override void DeserializeBody(BinaryReader reader) => throw new NotImplementedException();

    public override void DeserializeResponse(BinaryReader stream) => throw new NotImplementedException();

    public override bool Confirmed => false;

    public override bool Responded { get; }

    public override int Constructor => 1658238041;
  }
}
