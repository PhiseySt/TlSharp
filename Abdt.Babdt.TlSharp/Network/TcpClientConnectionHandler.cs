using System.Net.Sockets;

namespace Abdt.Babdt.TlSharp.Network
{
  public delegate TcpClient TcpClientConnectionHandler(string address, int port);
}
