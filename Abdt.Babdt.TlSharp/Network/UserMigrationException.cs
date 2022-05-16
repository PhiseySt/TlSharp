namespace Abdt.Babdt.TlSharp.Network
{
  internal class UserMigrationException : DataCenterMigrationException
  {
    internal UserMigrationException(int dc)
      : base(string.Format("User located on a different DC: {0}.", (object) dc), dc)
    {
    }
  }
}
