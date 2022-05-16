using System;

namespace Abdt.Babdt.TlSharp.Network
{
  internal abstract class DataCenterMigrationException : Exception
  {
    internal int DC { get; private set; }

    protected DataCenterMigrationException(string msg, int dc)
      : base(msg )
    {
      this.DC = dc;
    }
  }
}
