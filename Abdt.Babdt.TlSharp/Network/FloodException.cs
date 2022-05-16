using System;

namespace Abdt.Babdt.TlSharp.Network
{
  public class FloodException : Exception
  {
    public TimeSpan TimeToWait { get; private set; }

    internal FloodException(TimeSpan timeToWait)
      : base(string.Format("Flood prevention. Telegram now requires your program to do requests again only after {0} seconds have passed ({1} property).", (object) timeToWait.TotalSeconds, (object) nameof (TimeToWait)) + " If you think the culprit of this problem may lie in TLSharp's implementation, open a Github issue please.")
    {
      this.TimeToWait = timeToWait;
    }
  }
}
