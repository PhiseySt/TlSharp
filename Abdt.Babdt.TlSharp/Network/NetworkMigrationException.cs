namespace Abdt.Babdt.TlSharp.Network
{
  internal class NetworkMigrationException : DataCenterMigrationException
  {
    internal NetworkMigrationException(int dc)
      : base(string.Format("Network located on a different DC: {0}.", (object) dc), dc)
    {
    }
  }
}
