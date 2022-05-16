using System;
using System.IO;
using Abdt.Babdt.TlSharp.Utils;
using Abdt.Babdt.TlShema;

namespace Abdt.Babdt.TlSharp.Requests
{
  public class PingRequest : TLMethod
  {
    public override void SerializeBody(BinaryWriter writer)
    {
      writer.Write(this.Constructor);
      writer.Write(Helpers.GenerateRandomLong());
    }

    public override void DeserializeBody(BinaryReader reader) => throw new NotImplementedException();

    public override void DeserializeResponse(BinaryReader stream) => throw new NotImplementedException();

    public override int Constructor => 2059302892;
  }
}
