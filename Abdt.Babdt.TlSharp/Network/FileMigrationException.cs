namespace Abdt.Babdt.TlSharp.Network
{
  internal class FileMigrationException : DataCenterMigrationException
  {
    internal FileMigrationException(int dc)
      : base(string.Format("File located on a different DC: {0}.", (object) dc), dc)
    {
    }
  }
}
