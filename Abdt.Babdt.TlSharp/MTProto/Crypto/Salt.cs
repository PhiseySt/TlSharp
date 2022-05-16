using System;

namespace Abdt.Babdt.TlSharp.MTProto.Crypto
{
  public class Salt : IComparable<Salt>
  {
    private int validSince;
    private int validUntil;
    private ulong salt;

    public Salt(int validSince, int validUntil, ulong salt)
    {
      this.validSince = validSince;
      this.validUntil = validUntil;
      this.salt = salt;
    }

    public int ValidSince => this.validSince;

    public int ValidUntil => this.validUntil;

    public ulong Value => this.salt;

    public int CompareTo(Salt other) => this.validUntil.CompareTo(other.validSince);
  }
}
