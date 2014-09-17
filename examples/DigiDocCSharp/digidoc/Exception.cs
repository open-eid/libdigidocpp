using System;

namespace digidoc
{
    class DigidocException : System.ApplicationException
    {
        public DigidocException(string message) : base(message) { }
    }
}
