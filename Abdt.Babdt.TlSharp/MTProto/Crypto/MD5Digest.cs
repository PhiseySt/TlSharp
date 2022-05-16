using System;

namespace Abdt.Babdt.TlSharp.MTProto.Crypto
{
  public class MD5Digest : GeneralDigest
  {
    private const int DigestLength = 16;
    private static readonly int S11 = 7;
    private static readonly int S12 = 12;
    private static readonly int S13 = 17;
    private static readonly int S14 = 22;
    private static readonly int S21 = 5;
    private static readonly int S22 = 9;
    private static readonly int S23 = 14;
    private static readonly int S24 = 20;
    private static readonly int S31 = 4;
    private static readonly int S32 = 11;
    private static readonly int S33 = 16;
    private static readonly int S34 = 23;
    private static readonly int S41 = 6;
    private static readonly int S42 = 10;
    private static readonly int S43 = 15;
    private static readonly int S44 = 21;
    private readonly int[] X = new int[16];
    private int H1;
    private int H2;
    private int H3;
    private int H4;
    private int xOff;

    public MD5Digest() => this.Reset();

    public MD5Digest(MD5Digest t)
      : base((GeneralDigest) t)
    {
      this.H1 = t.H1;
      this.H2 = t.H2;
      this.H3 = t.H3;
      this.H4 = t.H4;
      Array.Copy((Array) t.X, 0, (Array) this.X, 0, t.X.Length);
      this.xOff = t.xOff;
    }

    public override string AlgorithmName => "MD5";

    public override int GetDigestSize() => 16;

    internal override void ProcessWord(byte[] input, int inOff)
    {
      this.X[this.xOff++] = (int) input[inOff] & (int) byte.MaxValue | ((int) input[inOff + 1] & (int) byte.MaxValue) << 8 | ((int) input[inOff + 2] & (int) byte.MaxValue) << 16 | ((int) input[inOff + 3] & (int) byte.MaxValue) << 24;
      if (this.xOff != 16)
        return;
      this.ProcessBlock();
    }

    internal override void ProcessLength(long bitLength)
    {
      if (this.xOff > 14)
        this.ProcessBlock();
      this.X[14] = (int) (bitLength & (long) uint.MaxValue);
      this.X[15] = (int) ((ulong) bitLength >> 32);
    }

    private void UnpackWord(int word, byte[] outBytes, int outOff)
    {
      outBytes[outOff] = (byte) word;
      outBytes[outOff + 1] = (byte) ((uint) word >> 8);
      outBytes[outOff + 2] = (byte) ((uint) word >> 16);
      outBytes[outOff + 3] = (byte) ((uint) word >> 24);
    }

    public override int DoFinal(byte[] output, int outOff)
    {
      this.Finish();
      this.UnpackWord(this.H1, output, outOff);
      this.UnpackWord(this.H2, output, outOff + 4);
      this.UnpackWord(this.H3, output, outOff + 8);
      this.UnpackWord(this.H4, output, outOff + 12);
      this.Reset();
      return 16;
    }

    public override void Reset()
    {
      base.Reset();
      this.H1 = 1732584193;
      this.H2 = -271733879;
      this.H3 = -1732584194;
      this.H4 = 271733878;
      this.xOff = 0;
      for (int index = 0; index != this.X.Length; ++index)
        this.X[index] = 0;
    }

    private int RotateLeft(int x, int n) => x << n | (int) ((uint) x >> 32 - n);

    private int F(int u, int v, int w) => u & v | ~u & w;

    private int G(int u, int v, int w) => u & w | v & ~w;

    private int H(int u, int v, int w) => u ^ v ^ w;

    private int K(int u, int v, int w) => v ^ (u | ~w);

    internal override void ProcessBlock()
    {
      int h1 = this.H1;
      int h2 = this.H2;
      int h3 = this.H3;
      int h4 = this.H4;
      int num1 = this.RotateLeft(h1 + this.F(h2, h3, h4) + this.X[0] - 680876936, MD5Digest.S11) + h2;
      int num2 = this.RotateLeft(h4 + this.F(num1, h2, h3) + this.X[1] - 389564586, MD5Digest.S12) + num1;
      int num3 = this.RotateLeft(h3 + this.F(num2, num1, h2) + this.X[2] + 606105819, MD5Digest.S13) + num2;
      int num4 = this.RotateLeft(h2 + this.F(num3, num2, num1) + this.X[3] - 1044525330, MD5Digest.S14) + num3;
      int num5 = this.RotateLeft(num1 + this.F(num4, num3, num2) + this.X[4] - 176418897, MD5Digest.S11) + num4;
      int num6 = this.RotateLeft(num2 + this.F(num5, num4, num3) + this.X[5] + 1200080426, MD5Digest.S12) + num5;
      int num7 = this.RotateLeft(num3 + this.F(num6, num5, num4) + this.X[6] - 1473231341, MD5Digest.S13) + num6;
      int num8 = this.RotateLeft(num4 + this.F(num7, num6, num5) + this.X[7] - 45705983, MD5Digest.S14) + num7;
      int num9 = this.RotateLeft(num5 + this.F(num8, num7, num6) + this.X[8] + 1770035416, MD5Digest.S11) + num8;
      int num10 = this.RotateLeft(num6 + this.F(num9, num8, num7) + this.X[9] - 1958414417, MD5Digest.S12) + num9;
      int num11 = this.RotateLeft(num7 + this.F(num10, num9, num8) + this.X[10] - 42063, MD5Digest.S13) + num10;
      int num12 = this.RotateLeft(num8 + this.F(num11, num10, num9) + this.X[11] - 1990404162, MD5Digest.S14) + num11;
      int num13 = this.RotateLeft(num9 + this.F(num12, num11, num10) + this.X[12] + 1804603682, MD5Digest.S11) + num12;
      int num14 = this.RotateLeft(num10 + this.F(num13, num12, num11) + this.X[13] - 40341101, MD5Digest.S12) + num13;
      int num15 = this.RotateLeft(num11 + this.F(num14, num13, num12) + this.X[14] - 1502002290, MD5Digest.S13) + num14;
      int num16 = this.RotateLeft(num12 + this.F(num15, num14, num13) + this.X[15] + 1236535329, MD5Digest.S14) + num15;
      int num17 = this.RotateLeft(num13 + this.G(num16, num15, num14) + this.X[1] - 165796510, MD5Digest.S21) + num16;
      int num18 = this.RotateLeft(num14 + this.G(num17, num16, num15) + this.X[6] - 1069501632, MD5Digest.S22) + num17;
      int num19 = this.RotateLeft(num15 + this.G(num18, num17, num16) + this.X[11] + 643717713, MD5Digest.S23) + num18;
      int num20 = this.RotateLeft(num16 + this.G(num19, num18, num17) + this.X[0] - 373897302, MD5Digest.S24) + num19;
      int num21 = this.RotateLeft(num17 + this.G(num20, num19, num18) + this.X[5] - 701558691, MD5Digest.S21) + num20;
      int num22 = this.RotateLeft(num18 + this.G(num21, num20, num19) + this.X[10] + 38016083, MD5Digest.S22) + num21;
      int num23 = this.RotateLeft(num19 + this.G(num22, num21, num20) + this.X[15] - 660478335, MD5Digest.S23) + num22;
      int num24 = this.RotateLeft(num20 + this.G(num23, num22, num21) + this.X[4] - 405537848, MD5Digest.S24) + num23;
      int num25 = this.RotateLeft(num21 + this.G(num24, num23, num22) + this.X[9] + 568446438, MD5Digest.S21) + num24;
      int num26 = this.RotateLeft(num22 + this.G(num25, num24, num23) + this.X[14] - 1019803690, MD5Digest.S22) + num25;
      int num27 = this.RotateLeft(num23 + this.G(num26, num25, num24) + this.X[3] - 187363961, MD5Digest.S23) + num26;
      int num28 = this.RotateLeft(num24 + this.G(num27, num26, num25) + this.X[8] + 1163531501, MD5Digest.S24) + num27;
      int num29 = this.RotateLeft(num25 + this.G(num28, num27, num26) + this.X[13] - 1444681467, MD5Digest.S21) + num28;
      int num30 = this.RotateLeft(num26 + this.G(num29, num28, num27) + this.X[2] - 51403784, MD5Digest.S22) + num29;
      int num31 = this.RotateLeft(num27 + this.G(num30, num29, num28) + this.X[7] + 1735328473, MD5Digest.S23) + num30;
      int num32 = this.RotateLeft(num28 + this.G(num31, num30, num29) + this.X[12] - 1926607734, MD5Digest.S24) + num31;
      int num33 = this.RotateLeft(num29 + this.H(num32, num31, num30) + this.X[5] - 378558, MD5Digest.S31) + num32;
      int num34 = this.RotateLeft(num30 + this.H(num33, num32, num31) + this.X[8] - 2022574463, MD5Digest.S32) + num33;
      int num35 = this.RotateLeft(num31 + this.H(num34, num33, num32) + this.X[11] + 1839030562, MD5Digest.S33) + num34;
      int num36 = this.RotateLeft(num32 + this.H(num35, num34, num33) + this.X[14] - 35309556, MD5Digest.S34) + num35;
      int num37 = this.RotateLeft(num33 + this.H(num36, num35, num34) + this.X[1] - 1530992060, MD5Digest.S31) + num36;
      int num38 = this.RotateLeft(num34 + this.H(num37, num36, num35) + this.X[4] + 1272893353, MD5Digest.S32) + num37;
      int num39 = this.RotateLeft(num35 + this.H(num38, num37, num36) + this.X[7] - 155497632, MD5Digest.S33) + num38;
      int num40 = this.RotateLeft(num36 + this.H(num39, num38, num37) + this.X[10] - 1094730640, MD5Digest.S34) + num39;
      int num41 = this.RotateLeft(num37 + this.H(num40, num39, num38) + this.X[13] + 681279174, MD5Digest.S31) + num40;
      int num42 = this.RotateLeft(num38 + this.H(num41, num40, num39) + this.X[0] - 358537222, MD5Digest.S32) + num41;
      int num43 = this.RotateLeft(num39 + this.H(num42, num41, num40) + this.X[3] - 722521979, MD5Digest.S33) + num42;
      int num44 = this.RotateLeft(num40 + this.H(num43, num42, num41) + this.X[6] + 76029189, MD5Digest.S34) + num43;
      int num45 = this.RotateLeft(num41 + this.H(num44, num43, num42) + this.X[9] - 640364487, MD5Digest.S31) + num44;
      int num46 = this.RotateLeft(num42 + this.H(num45, num44, num43) + this.X[12] - 421815835, MD5Digest.S32) + num45;
      int num47 = this.RotateLeft(num43 + this.H(num46, num45, num44) + this.X[15] + 530742520, MD5Digest.S33) + num46;
      int num48 = this.RotateLeft(num44 + this.H(num47, num46, num45) + this.X[2] - 995338651, MD5Digest.S34) + num47;
      int num49 = this.RotateLeft(num45 + this.K(num48, num47, num46) + this.X[0] - 198630844, MD5Digest.S41) + num48;
      int num50 = this.RotateLeft(num46 + this.K(num49, num48, num47) + this.X[7] + 1126891415, MD5Digest.S42) + num49;
      int num51 = this.RotateLeft(num47 + this.K(num50, num49, num48) + this.X[14] - 1416354905, MD5Digest.S43) + num50;
      int num52 = this.RotateLeft(num48 + this.K(num51, num50, num49) + this.X[5] - 57434055, MD5Digest.S44) + num51;
      int num53 = this.RotateLeft(num49 + this.K(num52, num51, num50) + this.X[12] + 1700485571, MD5Digest.S41) + num52;
      int num54 = this.RotateLeft(num50 + this.K(num53, num52, num51) + this.X[3] - 1894986606, MD5Digest.S42) + num53;
      int num55 = this.RotateLeft(num51 + this.K(num54, num53, num52) + this.X[10] - 1051523, MD5Digest.S43) + num54;
      int num56 = this.RotateLeft(num52 + this.K(num55, num54, num53) + this.X[1] - 2054922799, MD5Digest.S44) + num55;
      int num57 = this.RotateLeft(num53 + this.K(num56, num55, num54) + this.X[8] + 1873313359, MD5Digest.S41) + num56;
      int num58 = this.RotateLeft(num54 + this.K(num57, num56, num55) + this.X[15] - 30611744, MD5Digest.S42) + num57;
      int num59 = this.RotateLeft(num55 + this.K(num58, num57, num56) + this.X[6] - 1560198380, MD5Digest.S43) + num58;
      int num60 = this.RotateLeft(num56 + this.K(num59, num58, num57) + this.X[13] + 1309151649, MD5Digest.S44) + num59;
      int num61 = this.RotateLeft(num57 + this.K(num60, num59, num58) + this.X[4] - 145523070, MD5Digest.S41) + num60;
      int num62 = this.RotateLeft(num58 + this.K(num61, num60, num59) + this.X[11] - 1120210379, MD5Digest.S42) + num61;
      int u = this.RotateLeft(num59 + this.K(num62, num61, num60) + this.X[2] + 718787259, MD5Digest.S43) + num62;
      int num63 = this.RotateLeft(num60 + this.K(u, num62, num61) + this.X[9] - 343485551, MD5Digest.S44) + u;
      this.H1 += num61;
      this.H2 += num63;
      this.H3 += u;
      this.H4 += num62;
      this.xOff = 0;
      for (int index = 0; index != this.X.Length; ++index)
        this.X[index] = 0;
    }
  }
}
