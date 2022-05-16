using System;

namespace Abdt.Babdt.TlSharp
{
    public class InvalidPhoneCodeException : Exception
    {
        internal InvalidPhoneCodeException(string msg)
          : base(msg)
        {
        }
    }
}
