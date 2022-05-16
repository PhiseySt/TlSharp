namespace Abdt.Babdt.TlSharp
{
    internal class DataCenter
    {
        internal DataCenter(int? dcId, string address, int port)
        {
            this.DataCenterId = dcId;
            this.Address = address;
            this.Port = port;
        }

        internal DataCenter(string address, int port)
          : this(new int?(), address, port)
        {
        }

        internal int? DataCenterId { get; private set; }

        internal string Address { get; private set; }

        internal int Port { get; private set; }
    }
}
