namespace Abdt.Babdt.TlSharp.MTProto.Crypto
{
  public class FactorizedPair
  {
    private readonly BigInteger p;
    private readonly BigInteger q;

    public FactorizedPair(BigInteger p, BigInteger q)
    {
      this.p = p;
      this.q = q;
    }

    public FactorizedPair(long p, long q)
    {
      this.p = BigInteger.ValueOf(p);
      this.q = BigInteger.ValueOf(q);
    }

    public BigInteger Min => this.p.Min(this.q);

    public BigInteger Max => this.p.Max(this.q);

    public override string ToString() => string.Format("P: {0}, Q: {1}", (object) this.p, (object) this.q);
  }
}
