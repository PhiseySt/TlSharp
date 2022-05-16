using System;

namespace Abdt.Babdt.TlSharp
{
    public class MissingApiConfigurationException : Exception
    {
        internal MissingApiConfigurationException(string invalidParamName)
          : base("Your " + invalidParamName + " setting is missing.")
        {
        }
    }
}
