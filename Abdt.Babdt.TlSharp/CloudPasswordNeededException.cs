using System;

namespace Abdt.Babdt.TlSharp
{
    public class CloudPasswordNeededException : Exception
    {
        internal CloudPasswordNeededException(string msg)
          : base(msg)
        {
        }
    }
}
