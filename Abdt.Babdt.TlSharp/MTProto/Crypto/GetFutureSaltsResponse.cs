namespace Abdt.Babdt.TlSharp.MTProto.Crypto
{
  public class GetFutureSaltsResponse
  {
    private ulong requestId;
    private int now;
    private SaltCollection salts;

    public GetFutureSaltsResponse(ulong requestId, int now)
    {
      this.requestId = requestId;
      this.now = now;
    }

    public void AddSalt(Salt salt) => this.salts.Add(salt);

    public ulong RequestId => this.requestId;

    public int Now => this.now;

    public SaltCollection Salts => this.salts;
  }
}
