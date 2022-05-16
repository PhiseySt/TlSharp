namespace Abdt.Babdt.TlSharp.MTProto.Crypto
{
  public class AESKeyData
  {
    private readonly byte[] key;
    private readonly byte[] iv;

    public AESKeyData(byte[] key, byte[] iv)
    {
      this.key = key;
      this.iv = iv;
    }

    public byte[] Key => this.key;

    public byte[] Iv => this.iv;
  }
}
