using System.Collections.Generic;
using Abdt.Babdt.TlSharp.MTProto.Crypto;


namespace Abdt.Babdt.TlSharp.Auth
{
  public class Step1_Response
  {
    public byte[] Nonce { get; set; }

    public byte[] ServerNonce { get; set; }

    public BigInteger Pq { get; set; }

    public List<byte[]> Fingerprints { get; set; }
  }
}
