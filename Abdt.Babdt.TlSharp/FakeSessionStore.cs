namespace Abdt.Babdt.TlSharp
{
    public class FakeSessionStore : ISessionStore
    {
        public void Save(Session session)
        {
        }

        public Session Load(string sessionUserId) => (Session)null;
    }
}
