using System.Collections.Generic;

namespace Abdt.Babdt.TlSharp.MTProto.Crypto
{
  public class SaltCollection
  {
    private SortedSet<Salt> salts;

    public void Add(Salt salt) => this.salts.Add(salt);

    public int Count => this.salts.Count;
  }
}
