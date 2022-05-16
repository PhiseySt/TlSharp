namespace Abdt.Babdt.TlSharp.Network
{
  internal class PhoneMigrationException : DataCenterMigrationException
  {
    internal PhoneMigrationException(int dc)
      : base(string.Format("Phone number registered to a different DC: {0}.", (object) dc), dc)
    {
    }
  }
}
