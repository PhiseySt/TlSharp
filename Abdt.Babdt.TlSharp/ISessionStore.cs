namespace Abdt.Babdt.TlSharp
{
    public interface ISessionStore
    {
        void Save(Session session);

        Session Load(string sessionUserId);
    }
}
