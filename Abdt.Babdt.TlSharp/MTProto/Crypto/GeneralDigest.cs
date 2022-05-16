using System;

namespace Abdt.Babdt.TlSharp.MTProto.Crypto
{
  public abstract class GeneralDigest : IDigest
  {
    private const int BYTE_LENGTH = 64;
    private readonly byte[] xBuf;
    private long byteCount;
    private int xBufOff;

    internal GeneralDigest() => this.xBuf = new byte[4];

    internal GeneralDigest(GeneralDigest t)
    {
      this.xBuf = new byte[t.xBuf.Length];
      Array.Copy((Array) t.xBuf, 0, (Array) this.xBuf, 0, t.xBuf.Length);
      this.xBufOff = t.xBufOff;
      this.byteCount = t.byteCount;
    }

    public void Update(byte input)
    {
      this.xBuf[this.xBufOff++] = input;
      if (this.xBufOff == this.xBuf.Length)
      {
        this.ProcessWord(this.xBuf, 0);
        this.xBufOff = 0;
      }
      ++this.byteCount;
    }

    public void BlockUpdate(byte[] input, int inOff, int length)
    {
      for (; this.xBufOff != 0 && length > 0; --length)
      {
        this.Update(input[inOff]);
        ++inOff;
      }
      while (length > this.xBuf.Length)
      {
        this.ProcessWord(input, inOff);
        inOff += this.xBuf.Length;
        length -= this.xBuf.Length;
        this.byteCount += (long) this.xBuf.Length;
      }
      for (; length > 0; --length)
      {
        this.Update(input[inOff]);
        ++inOff;
      }
    }

    public virtual void Reset()
    {
      this.byteCount = 0L;
      this.xBufOff = 0;
      Array.Clear((Array) this.xBuf, 0, this.xBuf.Length);
    }

    public int GetByteLength() => 64;

    public abstract string AlgorithmName { get; }

    public abstract int GetDigestSize();

    public abstract int DoFinal(byte[] output, int outOff);

    public void Finish()
    {
      long bitLength = this.byteCount << 3;
      this.Update((byte) 128);
      while (this.xBufOff != 0)
        this.Update((byte) 0);
      this.ProcessLength(bitLength);
      this.ProcessBlock();
    }

    internal abstract void ProcessWord(byte[] input, int inOff);

    internal abstract void ProcessLength(long bitLength);

    internal abstract void ProcessBlock();
  }
}
