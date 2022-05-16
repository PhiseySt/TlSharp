using Abdt.Babdt.TlSharp.MTProto.Crypto;

namespace Abdt.Babdt.TlSharp.Auth
{
  public class Step3_Response
  {
    public AuthKey AuthKey { get; set; }

    public int TimeOffset { get; set; }
  }
}
