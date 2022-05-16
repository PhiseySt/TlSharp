namespace Abdt.Babdt.TlSharp.Auth
{
  public class Step2_Response
  {
    public byte[] Nonce { get; set; }

    public byte[] ServerNonce { get; set; }

    public byte[] NewNonce { get; set; }

    public byte[] EncryptedAnswer { get; set; }
  }
}
