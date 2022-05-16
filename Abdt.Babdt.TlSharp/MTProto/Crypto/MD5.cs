using System;
using System.Text;

namespace Abdt.Babdt.TlSharp.MTProto.Crypto
{
  public class MD5
  {
    private MD5Digest digest = new MD5Digest();

    public static string GetMd5String(string data) => BitConverter.ToString(MD5.GetMd5Bytes(Encoding.UTF8.GetBytes(data))).Replace("-", "").ToLower();

    public static byte[] GetMd5Bytes(byte[] data)
    {
      MD5Digest md5Digest = new MD5Digest();
      md5Digest.BlockUpdate(data, 0, data.Length);
      byte[] output = new byte[16];
      md5Digest.DoFinal(output, 0);
      return output;
    }

    public void Update(byte[] chunk) => this.digest.BlockUpdate(chunk, 0, chunk.Length);

    public void Update(byte[] chunk, int offset, int limit) => this.digest.BlockUpdate(chunk, offset, limit);

    public string FinalString()
    {
      byte[] output = new byte[16];
      this.digest.DoFinal(output, 0);
      return BitConverter.ToString(output).Replace("-", "").ToLower();
    }
  }
}
