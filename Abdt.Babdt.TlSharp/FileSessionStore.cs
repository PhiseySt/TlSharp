using System.IO;

namespace Abdt.Babdt.TlSharp
{
    public class FileSessionStore : ISessionStore
    {
        public void Save(Session session)
        {
            using (FileStream fileStream = new FileStream(session.SessionUserId + ".dat", FileMode.OpenOrCreate))
            {
                byte[] bytes = session.ToBytes();
                fileStream.Write(bytes, 0, bytes.Length);
            }
        }

        public Session Load(string sessionUserId)
        {
            string path = sessionUserId + ".dat";
            if (!File.Exists(path))
                return (Session)null;
            using (FileStream fileStream = new FileStream(path, FileMode.Open))
            {
                byte[] buffer = new byte[2048];
                fileStream.Read(buffer, 0, 2048);
                return Session.FromBytes(buffer, (ISessionStore)this, sessionUserId);
            }
        }
    }
}
