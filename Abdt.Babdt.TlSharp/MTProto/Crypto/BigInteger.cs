using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Abdt.Babdt.TlSharp.MTProto.Crypto
{
  [Serializable]
  public class BigInteger
  {
    private static readonly int[][] primeLists = new int[52][]
    {
      new int[8]{ 3, 5, 7, 11, 13, 17, 19, 23 },
      new int[5]{ 29, 31, 37, 41, 43 },
      new int[5]{ 47, 53, 59, 61, 67 },
      new int[4]{ 71, 73, 79, 83 },
      new int[4]{ 89, 97, 101, 103 },
      new int[4]{ 107, 109, 113, (int) sbyte.MaxValue },
      new int[4]{ 131, 137, 139, 149 },
      new int[4]{ 151, 157, 163, 167 },
      new int[4]{ 173, 179, 181, 191 },
      new int[4]{ 193, 197, 199, 211 },
      new int[3]{ 223, 227, 229 },
      new int[3]{ 233, 239, 241 },
      new int[3]{ 251, 257, 263 },
      new int[3]{ 269, 271, 277 },
      new int[3]{ 281, 283, 293 },
      new int[3]{ 307, 311, 313 },
      new int[3]{ 317, 331, 337 },
      new int[3]{ 347, 349, 353 },
      new int[3]{ 359, 367, 373 },
      new int[3]{ 379, 383, 389 },
      new int[3]{ 397, 401, 409 },
      new int[3]{ 419, 421, 431 },
      new int[3]{ 433, 439, 443 },
      new int[3]{ 449, 457, 461 },
      new int[3]{ 463, 467, 479 },
      new int[3]{ 487, 491, 499 },
      new int[3]{ 503, 509, 521 },
      new int[3]{ 523, 541, 547 },
      new int[3]{ 557, 563, 569 },
      new int[3]{ 571, 577, 587 },
      new int[3]{ 593, 599, 601 },
      new int[3]{ 607, 613, 617 },
      new int[3]{ 619, 631, 641 },
      new int[3]{ 643, 647, 653 },
      new int[3]{ 659, 661, 673 },
      new int[3]{ 677, 683, 691 },
      new int[3]{ 701, 709, 719 },
      new int[3]{ 727, 733, 739 },
      new int[3]{ 743, 751, 757 },
      new int[3]{ 761, 769, 773 },
      new int[3]{ 787, 797, 809 },
      new int[3]{ 811, 821, 823 },
      new int[3]{ 827, 829, 839 },
      new int[3]{ 853, 857, 859 },
      new int[3]{ 863, 877, 881 },
      new int[3]{ 883, 887, 907 },
      new int[3]{ 911, 919, 929 },
      new int[3]{ 937, 941, 947 },
      new int[3]{ 953, 967, 971 },
      new int[3]{ 977, 983, 991 },
      new int[3]{ 997, 1009, 1013 },
      new int[3]{ 1019, 1021, 1031 }
    };
    private static readonly int[] primeProducts;
    private const long IMASK = 4294967295;
    private static readonly ulong UIMASK = (ulong) uint.MaxValue;
    private static readonly int[] ZeroMagnitude = new int[0];
    private static readonly byte[] ZeroEncoding = new byte[0];
    public static readonly BigInteger Zero = new BigInteger(0, BigInteger.ZeroMagnitude, false);
    public static readonly BigInteger One = BigInteger.createUValueOf(1UL);
    public static readonly BigInteger Two = BigInteger.createUValueOf(2UL);
    public static readonly BigInteger Three = BigInteger.createUValueOf(3UL);
    public static readonly BigInteger Ten = BigInteger.createUValueOf(10UL);
    private static readonly int chunk2 = 1;
    private static readonly BigInteger radix2 = BigInteger.ValueOf(2L);
    private static readonly BigInteger radix2E = BigInteger.radix2.Pow(BigInteger.chunk2);
    private static readonly int chunk10 = 19;
    private static readonly BigInteger radix10 = BigInteger.ValueOf(10L);
    private static readonly BigInteger radix10E = BigInteger.radix10.Pow(BigInteger.chunk10);
    private static readonly int chunk16 = 16;
    private static readonly BigInteger radix16 = BigInteger.ValueOf(16L);
    private static readonly BigInteger radix16E = BigInteger.radix16.Pow(BigInteger.chunk16);
    private static readonly Random RandomSource = new Random();
    private const int BitsPerByte = 8;
    private const int BitsPerInt = 32;
    private const int BytesPerInt = 4;
    private int sign;
    private int[] magnitude;
    private int nBits = -1;
    private int nBitLength = -1;
    private long mQuote = -1;
    private static readonly byte[] rndMask = new byte[8]
    {
      byte.MaxValue,
      (byte) 127,
      (byte) 63,
      (byte) 31,
      (byte) 15,
      (byte) 7,
      (byte) 3,
      (byte) 1
    };
    private static readonly byte[] bitCounts = new byte[256]
    {
      (byte) 0,
      (byte) 1,
      (byte) 1,
      (byte) 2,
      (byte) 1,
      (byte) 2,
      (byte) 2,
      (byte) 3,
      (byte) 1,
      (byte) 2,
      (byte) 2,
      (byte) 3,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 1,
      (byte) 2,
      (byte) 2,
      (byte) 3,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 1,
      (byte) 2,
      (byte) 2,
      (byte) 3,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 1,
      (byte) 2,
      (byte) 2,
      (byte) 3,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 5,
      (byte) 6,
      (byte) 6,
      (byte) 7,
      (byte) 1,
      (byte) 2,
      (byte) 2,
      (byte) 3,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 5,
      (byte) 6,
      (byte) 6,
      (byte) 7,
      (byte) 2,
      (byte) 3,
      (byte) 3,
      (byte) 4,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 5,
      (byte) 6,
      (byte) 6,
      (byte) 7,
      (byte) 3,
      (byte) 4,
      (byte) 4,
      (byte) 5,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 5,
      (byte) 6,
      (byte) 6,
      (byte) 7,
      (byte) 4,
      (byte) 5,
      (byte) 5,
      (byte) 6,
      (byte) 5,
      (byte) 6,
      (byte) 6,
      (byte) 7,
      (byte) 5,
      (byte) 6,
      (byte) 6,
      (byte) 7,
      (byte) 6,
      (byte) 7,
      (byte) 7,
      (byte) 8
    };

    static BigInteger()
    {
      BigInteger.primeProducts = new int[BigInteger.primeLists.Length];
      for (int index1 = 0; index1 < BigInteger.primeLists.Length; ++index1)
      {
        int[] primeList = BigInteger.primeLists[index1];
        int num = 1;
        for (int index2 = 0; index2 < primeList.Length; ++index2)
          num *= primeList[index2];
        BigInteger.primeProducts[index1] = num;
      }
    }

    private static int GetByteLength(int nBits) => (nBits + 8 - 1) / 8;

    private BigInteger()
    {
    }

    private BigInteger(int signum, int[] mag, bool checkMag)
    {
      if (checkMag)
      {
        int sourceIndex = 0;
        while (sourceIndex < mag.Length && mag[sourceIndex] == 0)
          ++sourceIndex;
        if (sourceIndex == mag.Length)
        {
          this.magnitude = BigInteger.ZeroMagnitude;
        }
        else
        {
          this.sign = signum;
          if (sourceIndex == 0)
          {
            this.magnitude = mag;
          }
          else
          {
            this.magnitude = new int[mag.Length - sourceIndex];
            Array.Copy((Array) mag, sourceIndex, (Array) this.magnitude, 0, this.magnitude.Length);
          }
        }
      }
      else
      {
        this.sign = signum;
        this.magnitude = mag;
      }
    }

    public BigInteger(string value)
      : this(value, 10)
    {
    }

    public BigInteger(string str, int radix)
    {
      if (str.Length == 0)
        throw new FormatException("Zero length BigInteger");
      NumberStyles style;
      int length;
      BigInteger bigInteger1;
      BigInteger val;
      switch (radix)
      {
        case 2:
          style = NumberStyles.Integer;
          length = BigInteger.chunk2;
          bigInteger1 = BigInteger.radix2;
          val = BigInteger.radix2E;
          break;
        case 10:
          style = NumberStyles.Integer;
          length = BigInteger.chunk10;
          bigInteger1 = BigInteger.radix10;
          val = BigInteger.radix10E;
          break;
        case 16:
          style = NumberStyles.AllowHexSpecifier;
          length = BigInteger.chunk16;
          bigInteger1 = BigInteger.radix16;
          val = BigInteger.radix16E;
          break;
        default:
          throw new FormatException("Only bases 2, 10, or 16 allowed");
      }
      int num1 = 0;
      this.sign = 1;
      if (str[0] == '-')
      {
        if (str.Length == 1)
          throw new FormatException("Zero length BigInteger");
        this.sign = -1;
        num1 = 1;
      }
      while (num1 < str.Length && int.Parse(str[num1].ToString(), style) == 0)
        ++num1;
      if (num1 >= str.Length)
      {
        this.sign = 0;
        this.magnitude = BigInteger.ZeroMagnitude;
      }
      else
      {
        BigInteger bigInteger2 = BigInteger.Zero;
        int num2 = num1 + length;
        if (num2 <= str.Length)
        {
          do
          {
            string s = str.Substring(num1, length);
            ulong num3 = ulong.Parse(s, style);
            BigInteger uvalueOf = BigInteger.createUValueOf(num3);
            BigInteger bigInteger3;
            switch (radix)
            {
              case 2:
                if (num3 > 1UL)
                  throw new FormatException("Bad character in radix 2 string: " + s);
                bigInteger3 = bigInteger2.ShiftLeft(1);
                break;
              case 16:
                bigInteger3 = bigInteger2.ShiftLeft(64);
                break;
              default:
                bigInteger3 = bigInteger2.Multiply(val);
                break;
            }
            bigInteger2 = bigInteger3.Add(uvalueOf);
            num1 = num2;
            num2 += length;
          }
          while (num2 <= str.Length);
        }
        if (num1 < str.Length)
        {
          string s = str.Substring(num1);
          BigInteger uvalueOf = BigInteger.createUValueOf(ulong.Parse(s, style));
          if (bigInteger2.sign > 0)
          {
            switch (radix)
            {
              case 2:
                bigInteger2 = bigInteger2.Add(uvalueOf);
                break;
              case 16:
                bigInteger2 = bigInteger2.ShiftLeft(s.Length << 2);
                goto case 2;
              default:
                bigInteger2 = bigInteger2.Multiply(bigInteger1.Pow(s.Length));
                goto case 2;
            }
          }
          else
            bigInteger2 = uvalueOf;
        }
        this.magnitude = bigInteger2.magnitude;
      }
    }

    public BigInteger(byte[] bytes)
      : this(bytes, 0, bytes.Length)
    {
    }

    public BigInteger(byte[] bytes, int offset, int length)
    {
      if (length == 0)
        throw new FormatException("Zero length BigInteger");
      if ((sbyte) bytes[offset] < (sbyte) 0)
      {
        this.sign = -1;
        int num = offset + length;
        int index1 = offset;
        while (index1 < num && bytes[index1] == byte.MaxValue)
          ++index1;
        if (index1 >= num)
        {
          this.magnitude = BigInteger.One.magnitude;
        }
        else
        {
          int length1 = num - index1;
          byte[] bytes1 = new byte[length1];
          int index2 = 0;
          while (index2 < length1)
            bytes1[index2++] = (byte) ~bytes[index1++];
          while (bytes1[--index2] == byte.MaxValue)
            bytes1[index2] = (byte) 0;
          ++bytes1[index2];
          this.magnitude = BigInteger.MakeMagnitude(bytes1, 0, bytes1.Length);
        }
      }
      else
      {
        this.magnitude = BigInteger.MakeMagnitude(bytes, offset, length);
        this.sign = this.magnitude.Length != 0 ? 1 : 0;
      }
    }

    private static int[] MakeMagnitude(byte[] bytes, int offset, int length)
    {
      int num1 = offset + length;
      int index1 = offset;
      while (index1 < num1 && bytes[index1] == (byte) 0)
        ++index1;
      if (index1 >= num1)
        return BigInteger.ZeroMagnitude;
      int length1 = (num1 - index1 + 3) / 4;
      int num2 = (num1 - index1) % 4;
      if (num2 == 0)
        num2 = 4;
      if (length1 < 1)
        return BigInteger.ZeroMagnitude;
      int[] numArray = new int[length1];
      int num3 = 0;
      int index2 = 0;
      for (int index3 = index1; index3 < num1; ++index3)
      {
        num3 = num3 << 8 | (int) bytes[index3] & (int) byte.MaxValue;
        --num2;
        if (num2 <= 0)
        {
          numArray[index2] = num3;
          ++index2;
          num2 = 4;
          num3 = 0;
        }
      }
      if (index2 < numArray.Length)
        numArray[index2] = num3;
      return numArray;
    }

    public BigInteger(int sign, byte[] bytes)
      : this(sign, bytes, 0, bytes.Length)
    {
    }

    public BigInteger(int sign, byte[] bytes, int offset, int length)
    {
      if (sign < -1 || sign > 1)
        throw new FormatException("Invalid sign value");
      if (sign == 0)
      {
        this.magnitude = BigInteger.ZeroMagnitude;
      }
      else
      {
        this.magnitude = BigInteger.MakeMagnitude(bytes, offset, length);
        this.sign = this.magnitude.Length < 1 ? 0 : sign;
      }
    }

    public BigInteger(int sizeInBits, Random random)
    {
      if (sizeInBits < 0)
        throw new ArgumentException("sizeInBits must be non-negative");
      this.nBits = -1;
      this.nBitLength = -1;
      if (sizeInBits == 0)
      {
        this.magnitude = BigInteger.ZeroMagnitude;
      }
      else
      {
        int byteLength = BigInteger.GetByteLength(sizeInBits);
        byte[] numArray = new byte[byteLength];
        random.NextBytes(numArray);
        numArray[0] &= BigInteger.rndMask[8 * byteLength - sizeInBits];
        this.magnitude = BigInteger.MakeMagnitude(numArray, 0, numArray.Length);
        this.sign = this.magnitude.Length < 1 ? 0 : 1;
      }
    }

    public BigInteger(int bitLength, int certainty, Random random)
    {
      if (bitLength < 2)
        throw new ArithmeticException("bitLength < 2");
      this.sign = 1;
      this.nBitLength = bitLength;
      if (bitLength == 2)
      {
        this.magnitude = random.Next(2) == 0 ? BigInteger.Two.magnitude : BigInteger.Three.magnitude;
      }
      else
      {
        int byteLength = BigInteger.GetByteLength(bitLength);
        byte[] numArray = new byte[byteLength];
        int index1 = 8 * byteLength - bitLength;
        byte num1 = BigInteger.rndMask[index1];
label_5:
        do
        {
          random.NextBytes(numArray);
          numArray[0] &= num1;
          numArray[0] |= (byte) (1 << 7 - index1);
          numArray[byteLength - 1] |= (byte) 1;
          this.magnitude = BigInteger.MakeMagnitude(numArray, 0, numArray.Length);
          this.nBits = -1;
          this.mQuote = -1L;
          if (certainty < 1 || this.CheckProbablePrime(certainty, random))
            goto label_9;
        }
        while (bitLength <= 32);
        goto label_7;
label_9:
        return;
label_7:
        for (int index2 = 0; index2 < 10000; ++index2)
        {
          int num2 = 33 + random.Next(bitLength - 2);
          this.magnitude[this.magnitude.Length - (num2 >> 5)] ^= 1 << num2;
          this.magnitude[this.magnitude.Length - 1] ^= random.Next() + 1 << 1;
          this.mQuote = -1L;
          if (this.CheckProbablePrime(certainty, random))
            return;
        }
        goto label_5;
      }
    }

    public BigInteger Abs() => this.sign < 0 ? this.Negate() : this;

    private static int[] AddMagnitudes(int[] a, int[] b)
    {
      int index = a.Length - 1;
      int num1 = b.Length - 1;
      long num2 = 0;
      while (num1 >= 0)
      {
        long num3 = num2 + ((long) (uint) a[index] + (long) (uint) b[num1--]);
        a[index--] = (int) num3;
        num2 = (long) ((ulong) num3 >> 32);
      }
      if (num2 != 0L)
      {
        while (index >= 0 && ++a[index--] == 0)
          ;
      }
      return a;
    }

    public BigInteger Add(BigInteger value)
    {
      if (this.sign == 0)
        return value;
      if (this.sign == value.sign)
        return this.AddToMagnitude(value.magnitude);
      if (value.sign == 0)
        return this;
      return value.sign < 0 ? this.Subtract(value.Negate()) : value.Subtract(this.Negate());
    }

    private BigInteger AddToMagnitude(int[] magToAdd)
    {
      int[] numArray;
      int[] b;
      if (this.magnitude.Length < magToAdd.Length)
      {
        numArray = magToAdd;
        b = this.magnitude;
      }
      else
      {
        numArray = this.magnitude;
        b = magToAdd;
      }
      uint maxValue = uint.MaxValue;
      if (numArray.Length == b.Length)
        maxValue -= (uint) b[0];
      bool checkMag = (uint) numArray[0] >= maxValue;
      int[] a;
      if (checkMag)
      {
        a = new int[numArray.Length + 1];
        numArray.CopyTo((Array) a, 1);
      }
      else
        a = (int[]) numArray.Clone();
      return new BigInteger(this.sign, BigInteger.AddMagnitudes(a, b), checkMag);
    }

    public BigInteger And(BigInteger value)
    {
      if (this.sign == 0 || value.sign == 0)
        return BigInteger.Zero;
      int[] numArray1 = this.sign > 0 ? this.magnitude : this.Add(BigInteger.One).magnitude;
      int[] numArray2 = value.sign > 0 ? value.magnitude : value.Add(BigInteger.One).magnitude;
      bool flag = this.sign < 0 && value.sign < 0;
      int[] mag = new int[Math.Max(numArray1.Length, numArray2.Length)];
      int num1 = mag.Length - numArray1.Length;
      int num2 = mag.Length - numArray2.Length;
      for (int index = 0; index < mag.Length; ++index)
      {
        int num3 = index >= num1 ? numArray1[index - num1] : 0;
        int num4 = index >= num2 ? numArray2[index - num2] : 0;
        if (this.sign < 0)
          num3 = ~num3;
        if (value.sign < 0)
          num4 = ~num4;
        mag[index] = num3 & num4;
        if (flag)
          mag[index] = ~mag[index];
      }
      BigInteger bigInteger = new BigInteger(1, mag, true);
      if (flag)
        bigInteger = bigInteger.Not();
      return bigInteger;
    }

    public BigInteger AndNot(BigInteger val) => this.And(val.Not());

    public int BitCount
    {
      get
      {
        if (this.nBits == -1)
        {
          if (this.sign < 0)
          {
            this.nBits = this.Not().BitCount;
          }
          else
          {
            int num = 0;
            for (int index = 0; index < this.magnitude.Length; ++index)
              num = num + (int) BigInteger.bitCounts[(int) (byte) this.magnitude[index]] + (int) BigInteger.bitCounts[(int) (byte) (this.magnitude[index] >> 8)] + (int) BigInteger.bitCounts[(int) (byte) (this.magnitude[index] >> 16)] + (int) BigInteger.bitCounts[(int) (byte) (this.magnitude[index] >> 24)];
            this.nBits = num;
          }
        }
        return this.nBits;
      }
    }

    private int calcBitLength(int indx, int[] mag)
    {
      for (; indx < mag.Length; ++indx)
      {
        if (mag[indx] != 0)
        {
          int num1 = 32 * (mag.Length - indx - 1);
          int w = mag[indx];
          int num2 = num1 + BigInteger.BitLen(w);
          if (this.sign < 0 && (w & -w) == w)
          {
            while (++indx < mag.Length)
            {
              if (mag[indx] != 0)
                goto label_8;
            }
            --num2;
          }
label_8:
          return num2;
        }
      }
      return 0;
    }

    public int BitLength
    {
      get
      {
        if (this.nBitLength == -1)
          this.nBitLength = this.sign == 0 ? 0 : this.calcBitLength(0, this.magnitude);
        return this.nBitLength;
      }
    }

    private static int BitLen(int w)
    {
      if (w >= 32768)
        return w >= 8388608 ? (w >= 134217728 ? (w >= 536870912 ? (w >= 1073741824 ? 31 : 30) : (w >= 268435456 ? 29 : 28)) : (w >= 33554432 ? (w >= 67108864 ? 27 : 26) : (w >= 16777216 ? 25 : 24))) : (w >= 524288 ? (w >= 2097152 ? (w >= 4194304 ? 23 : 22) : (w >= 1048576 ? 21 : 20)) : (w >= 131072 ? (w >= 262144 ? 19 : 18) : (w >= 65536 ? 17 : 16)));
      if (w >= 128)
        return w >= 2048 ? (w >= 8192 ? (w >= 16384 ? 15 : 14) : (w >= 4096 ? 13 : 12)) : (w >= 512 ? (w >= 1024 ? 11 : 10) : (w >= 256 ? 9 : 8));
      if (w >= 8)
        return w >= 32 ? (w >= 64 ? 7 : 6) : (w >= 16 ? 5 : 4);
      if (w >= 2)
        return w >= 4 ? 3 : 2;
      if (w >= 1)
        return 1;
      return w >= 0 ? 0 : 32;
    }

    private bool QuickPow2Check() => this.sign > 0 && this.nBits == 1;

    public int CompareTo(object obj) => this.CompareTo((BigInteger) obj);

    private static int CompareTo(int xIndx, int[] x, int yIndx, int[] y)
    {
      while (xIndx != x.Length && x[xIndx] == 0)
        ++xIndx;
      while (yIndx != y.Length && y[yIndx] == 0)
        ++yIndx;
      return BigInteger.CompareNoLeadingZeroes(xIndx, x, yIndx, y);
    }

    private static int CompareNoLeadingZeroes(int xIndx, int[] x, int yIndx, int[] y)
    {
      int num1 = x.Length - y.Length - (xIndx - yIndx);
      if (num1 != 0)
        return num1 >= 0 ? 1 : -1;
      while (xIndx < x.Length)
      {
        uint num2 = (uint) x[xIndx++];
        uint num3 = (uint) y[yIndx++];
        if ((int) num2 != (int) num3)
          return num2 >= num3 ? 1 : -1;
      }
      return 0;
    }

    public int CompareTo(BigInteger value)
    {
      if (this.sign < value.sign)
        return -1;
      if (this.sign > value.sign)
        return 1;
      return this.sign != 0 ? this.sign * BigInteger.CompareNoLeadingZeroes(0, this.magnitude, 0, value.magnitude) : 0;
    }

    private int[] Divide(int[] x, int[] y)
    {
      int index1 = 0;
      while (index1 < x.Length && x[index1] == 0)
        ++index1;
      int index2 = 0;
      while (index2 < y.Length && y[index2] == 0)
        ++index2;
      int num1 = BigInteger.CompareNoLeadingZeroes(index1, x, index2, y);
      int[] a;
      if (num1 > 0)
      {
        int num2 = this.calcBitLength(index2, y);
        int num3 = this.calcBitLength(index1, x);
        int n1 = num3 - num2;
        int start = 0;
        int index3 = 0;
        int num4 = num2;
        int[] numArray1;
        int[] numArray2;
        if (n1 > 0)
        {
          numArray1 = new int[(n1 >> 5) + 1];
          numArray1[0] = 1 << n1 % 32;
          numArray2 = BigInteger.ShiftLeft(y, n1);
          num4 += n1;
        }
        else
        {
          numArray1 = new int[1]{ 1 };
          int length = y.Length - index2;
          numArray2 = new int[length];
          Array.Copy((Array) y, index2, (Array) numArray2, 0, length);
        }
        a = new int[numArray1.Length];
label_11:
        if (num4 < num3 || BigInteger.CompareNoLeadingZeroes(index1, x, index3, numArray2) >= 0)
        {
          BigInteger.Subtract(index1, x, index3, numArray2);
          BigInteger.AddMagnitudes(a, numArray1);
          while (x[index1] == 0)
          {
            if (++index1 == x.Length)
              return a;
          }
          num3 = 32 * (x.Length - index1 - 1) + BigInteger.BitLen(x[index1]);
          if (num3 <= num2)
          {
            if (num3 < num2)
              return a;
            num1 = BigInteger.CompareNoLeadingZeroes(index1, x, index2, y);
            if (num1 <= 0)
              goto label_30;
          }
        }
        int n2 = num4 - num3;
        if (n2 == 1 && (uint) numArray2[index3] >> 1 > (uint) x[index1])
          ++n2;
        if (n2 < 2)
        {
          BigInteger.ShiftRightOneInPlace(index3, numArray2);
          --num4;
          BigInteger.ShiftRightOneInPlace(start, numArray1);
        }
        else
        {
          BigInteger.ShiftRightInPlace(index3, numArray2, n2);
          num4 -= n2;
          BigInteger.ShiftRightInPlace(start, numArray1, n2);
        }
        while (numArray2[index3] == 0)
          ++index3;
        while (numArray1[start] == 0)
          ++start;
        goto label_11;
      }
      else
        a = new int[1];
label_30:
      if (num1 == 0)
      {
        BigInteger.AddMagnitudes(a, BigInteger.One.magnitude);
        Array.Clear((Array) x, index1, x.Length - index1);
      }
      return a;
    }

    public BigInteger Divide(BigInteger val)
    {
      if (val.sign == 0)
        throw new ArithmeticException("Division by zero error");
      if (this.sign == 0)
        return BigInteger.Zero;
      if (val.QuickPow2Check())
      {
        BigInteger bigInteger = this.Abs().ShiftRight(val.Abs().BitLength - 1);
        return val.sign != this.sign ? bigInteger.Negate() : bigInteger;
      }
      int[] x = (int[]) this.magnitude.Clone();
      return new BigInteger(this.sign * val.sign, this.Divide(x, val.magnitude), true);
    }

    public BigInteger[] DivideAndRemainder(BigInteger val)
    {
      if (val.sign == 0)
        throw new ArithmeticException("Division by zero error");
      BigInteger[] bigIntegerArray = new BigInteger[2];
      if (this.sign == 0)
      {
        bigIntegerArray[0] = BigInteger.Zero;
        bigIntegerArray[1] = BigInteger.Zero;
      }
      else if (val.QuickPow2Check())
      {
        int n = val.Abs().BitLength - 1;
        BigInteger bigInteger = this.Abs().ShiftRight(n);
        int[] mag = this.LastNBits(n);
        bigIntegerArray[0] = val.sign == this.sign ? bigInteger : bigInteger.Negate();
        bigIntegerArray[1] = new BigInteger(this.sign, mag, true);
      }
      else
      {
        int[] numArray = (int[]) this.magnitude.Clone();
        int[] mag = this.Divide(numArray, val.magnitude);
        bigIntegerArray[0] = new BigInteger(this.sign * val.sign, mag, true);
        bigIntegerArray[1] = new BigInteger(this.sign, numArray, true);
      }
      return bigIntegerArray;
    }

    public override bool Equals(object obj)
    {
      if (obj == this)
        return true;
      if (!(obj is BigInteger bigInteger) || bigInteger.sign != this.sign || bigInteger.magnitude.Length != this.magnitude.Length)
        return false;
      for (int index = 0; index < this.magnitude.Length; ++index)
      {
        if (bigInteger.magnitude[index] != this.magnitude[index])
          return false;
      }
      return true;
    }

    public BigInteger Gcd(BigInteger value)
    {
      if (value.sign == 0)
        return this.Abs();
      if (this.sign == 0)
        return value.Abs();
      BigInteger bigInteger1 = this;
      BigInteger bigInteger2;
      for (BigInteger m = value; m.sign != 0; m = bigInteger2)
      {
        bigInteger2 = bigInteger1.Mod(m);
        bigInteger1 = m;
      }
      return bigInteger1;
    }

    public override int GetHashCode()
    {
      int length = this.magnitude.Length;
      if (this.magnitude.Length != 0)
      {
        length ^= this.magnitude[0];
        if (this.magnitude.Length > 1)
          length ^= this.magnitude[this.magnitude.Length - 1];
      }
      return this.sign >= 0 ? length : ~length;
    }

    private BigInteger Inc()
    {
      if (this.sign == 0)
        return BigInteger.One;
      return this.sign < 0 ? new BigInteger(-1, BigInteger.doSubBigLil(this.magnitude, BigInteger.One.magnitude), true) : this.AddToMagnitude(BigInteger.One.magnitude);
    }

    public int IntValue
    {
      get
      {
        if (this.sign == 0)
          return 0;
        return this.sign <= 0 ? -this.magnitude[this.magnitude.Length - 1] : this.magnitude[this.magnitude.Length - 1];
      }
    }

    public bool IsProbablePrime(int certainty)
    {
      if (certainty <= 0)
        return true;
      BigInteger bigInteger = this.Abs();
      if (!bigInteger.TestBit(0))
        return bigInteger.Equals((object) BigInteger.Two);
      return !bigInteger.Equals((object) BigInteger.One) && bigInteger.CheckProbablePrime(certainty, BigInteger.RandomSource);
    }

    private bool CheckProbablePrime(int certainty, Random random)
    {
      int num1 = Math.Min(this.BitLength - 1, BigInteger.primeLists.Length);
      for (int index = 0; index < num1; ++index)
      {
        int num2 = this.Remainder(BigInteger.primeProducts[index]);
        foreach (int num3 in BigInteger.primeLists[index])
        {
          if (num2 % num3 == 0)
            return this.BitLength < 16 && this.IntValue == num3;
        }
      }
      return this.RabinMillerTest(certainty, random);
    }

    internal bool RabinMillerTest(int certainty, Random random)
    {
      BigInteger m = this;
      BigInteger bigInteger1 = m.Subtract(BigInteger.One);
      int lowestSetBit = bigInteger1.GetLowestSetBit();
      BigInteger exponent = bigInteger1.ShiftRight(lowestSetBit);
      do
      {
        BigInteger bigInteger2;
        do
        {
          bigInteger2 = new BigInteger(m.BitLength, random);
        }
        while (bigInteger2.CompareTo(BigInteger.One) <= 0 || bigInteger2.CompareTo(bigInteger1) >= 0);
        BigInteger bigInteger3 = bigInteger2.ModPow(exponent, m);
        if (!bigInteger3.Equals((object) BigInteger.One))
        {
          int num = 0;
          while (!bigInteger3.Equals((object) bigInteger1))
          {
            if (++num == lowestSetBit)
              return false;
            bigInteger3 = bigInteger3.ModPow(BigInteger.Two, m);
            if (bigInteger3.Equals((object) BigInteger.One))
              return false;
          }
        }
        certainty -= 2;
      }
      while (certainty > 0);
      return true;
    }

    public long LongValue
    {
      get
      {
        if (this.sign == 0)
          return 0;
        long num = this.magnitude.Length <= 1 ? (long) this.magnitude[this.magnitude.Length - 1] & (long) uint.MaxValue : (long) this.magnitude[this.magnitude.Length - 2] << 32 | (long) this.magnitude[this.magnitude.Length - 1] & (long) uint.MaxValue;
        return this.sign >= 0 ? num : -num;
      }
    }

    public BigInteger Max(BigInteger value) => this.CompareTo(value) <= 0 ? value : this;

    public BigInteger Min(BigInteger value) => this.CompareTo(value) >= 0 ? value : this;

    public BigInteger Mod(BigInteger m)
    {
      BigInteger bigInteger = m.sign >= 1 ? this.Remainder(m) : throw new ArithmeticException("Modulus must be positive");
      return bigInteger.sign < 0 ? bigInteger.Add(m) : bigInteger;
    }

    public BigInteger ModInverse(BigInteger m)
    {
      if (m.sign < 1)
        throw new ArithmeticException("Modulus must be positive");
      BigInteger u1Out = new BigInteger();
      if (!BigInteger.ExtEuclid(this.Mod(m), m, u1Out, (BigInteger) null).Equals((object) BigInteger.One))
        throw new ArithmeticException("Numbers not relatively prime.");
      if (u1Out.sign < 0)
      {
        u1Out.sign = 1;
        u1Out.magnitude = BigInteger.doSubBigLil(m.magnitude, u1Out.magnitude);
      }
      return u1Out;
    }

    private static BigInteger ExtEuclid(
      BigInteger a,
      BigInteger b,
      BigInteger u1Out,
      BigInteger u2Out)
    {
      BigInteger bigInteger1 = BigInteger.One;
      BigInteger bigInteger2 = a;
      BigInteger bigInteger3 = BigInteger.Zero;
      BigInteger[] bigIntegerArray;
      for (BigInteger val = b; val.sign > 0; val = bigIntegerArray[1])
      {
        bigIntegerArray = bigInteger2.DivideAndRemainder(val);
        BigInteger n = bigInteger3.Multiply(bigIntegerArray[0]);
        BigInteger bigInteger4 = bigInteger1.Subtract(n);
        bigInteger1 = bigInteger3;
        bigInteger3 = bigInteger4;
        bigInteger2 = val;
      }
      if (u1Out != null)
      {
        u1Out.sign = bigInteger1.sign;
        u1Out.magnitude = bigInteger1.magnitude;
      }
      if (u2Out != null)
      {
        BigInteger n = bigInteger1.Multiply(a);
        BigInteger bigInteger5 = bigInteger2.Subtract(n).Divide(b);
        u2Out.sign = bigInteger5.sign;
        u2Out.magnitude = bigInteger5.magnitude;
      }
      return bigInteger2;
    }

    private static void ZeroOut(int[] x) => Array.Clear((Array) x, 0, x.Length);

    public BigInteger ModPow(BigInteger exponent, BigInteger m)
    {
      if (m.sign < 1)
        throw new ArithmeticException("Modulus must be positive");
      if (m.Equals((object) BigInteger.One))
        return BigInteger.Zero;
      if (exponent.sign == 0)
        return BigInteger.One;
      if (this.sign == 0)
        return BigInteger.Zero;
      int[] numArray1 = (int[]) null;
      int[] numArray2 = (int[]) null;
      bool flag = (m.magnitude[m.magnitude.Length - 1] & 1) == 1;
      long mQuote = 0;
      if (flag)
      {
        mQuote = m.GetMQuote();
        numArray1 = this.ShiftLeft(32 * m.magnitude.Length).Mod(m).magnitude;
        flag = numArray1.Length <= m.magnitude.Length;
        if (flag)
        {
          numArray2 = new int[m.magnitude.Length + 1];
          if (numArray1.Length < m.magnitude.Length)
          {
            int[] numArray3 = new int[m.magnitude.Length];
            numArray1.CopyTo((Array) numArray3, numArray3.Length - numArray1.Length);
            numArray1 = numArray3;
          }
        }
      }
      if (!flag)
      {
        if (this.magnitude.Length <= m.magnitude.Length)
        {
          numArray1 = new int[m.magnitude.Length];
          this.magnitude.CopyTo((Array) numArray1, numArray1.Length - this.magnitude.Length);
        }
        else
        {
          BigInteger bigInteger = this.Remainder(m);
          numArray1 = new int[m.magnitude.Length];
          bigInteger.magnitude.CopyTo((Array) numArray1, numArray1.Length - bigInteger.magnitude.Length);
        }
        numArray2 = new int[m.magnitude.Length * 2];
      }
      int[] numArray4 = new int[m.magnitude.Length];
      for (int index = 0; index < exponent.magnitude.Length; ++index)
      {
        int num1 = exponent.magnitude[index];
        int num2 = 0;
        if (index == 0)
        {
          while (num1 > 0)
          {
            num1 <<= 1;
            ++num2;
          }
          numArray1.CopyTo((Array) numArray4, 0);
          num1 <<= 1;
          ++num2;
        }
        for (; num1 != 0; num1 <<= 1)
        {
          if (flag)
          {
            BigInteger.MultiplyMonty(numArray2, numArray4, numArray4, m.magnitude, mQuote);
          }
          else
          {
            BigInteger.Square(numArray2, numArray4);
            this.Remainder(numArray2, m.magnitude);
            Array.Copy((Array) numArray2, numArray2.Length - numArray4.Length, (Array) numArray4, 0, numArray4.Length);
            BigInteger.ZeroOut(numArray2);
          }
          ++num2;
          if (num1 < 0)
          {
            if (flag)
            {
              BigInteger.MultiplyMonty(numArray2, numArray4, numArray1, m.magnitude, mQuote);
            }
            else
            {
              BigInteger.Multiply(numArray2, numArray4, numArray1);
              this.Remainder(numArray2, m.magnitude);
              Array.Copy((Array) numArray2, numArray2.Length - numArray4.Length, (Array) numArray4, 0, numArray4.Length);
              BigInteger.ZeroOut(numArray2);
            }
          }
        }
        for (; num2 < 32; ++num2)
        {
          if (flag)
          {
            BigInteger.MultiplyMonty(numArray2, numArray4, numArray4, m.magnitude, mQuote);
          }
          else
          {
            BigInteger.Square(numArray2, numArray4);
            this.Remainder(numArray2, m.magnitude);
            Array.Copy((Array) numArray2, numArray2.Length - numArray4.Length, (Array) numArray4, 0, numArray4.Length);
            BigInteger.ZeroOut(numArray2);
          }
        }
      }
      if (flag)
      {
        BigInteger.ZeroOut(numArray1);
        numArray1[numArray1.Length - 1] = 1;
        BigInteger.MultiplyMonty(numArray2, numArray4, numArray1, m.magnitude, mQuote);
      }
      BigInteger bigInteger1 = new BigInteger(1, numArray4, true);
      return exponent.sign <= 0 ? bigInteger1.ModInverse(m) : bigInteger1;
    }

    private static int[] Square(int[] w, int[] x)
    {
      int index1 = w.Length - 1;
      for (int index2 = x.Length - 1; index2 != 0; --index2)
      {
        ulong num1 = (ulong) (uint) x[index2];
        ulong num2 = num1 * num1;
        ulong num3 = num2 >> 32;
        ulong num4 = (ulong) (uint) num2 + (ulong) (uint) w[index1];
        w[index1] = (int) (uint) num4;
        ulong num5 = num3 + (num4 >> 32);
        for (int index3 = index2 - 1; index3 >= 0; --index3)
        {
          --index1;
          ulong num6 = num1 * (ulong) (uint) x[index3];
          ulong num7 = num6 >> 31;
          ulong num8 = (ulong) (uint) (num6 << 1) + (num5 + (ulong) (uint) w[index1]);
          w[index1] = (int) (uint) num8;
          num5 = num7 + (num8 >> 32);
        }
        int index4;
        ulong num9 = num5 + (ulong) (uint) w[index4 = index1 - 1];
        w[index4] = (int) (uint) num9;
        int index5;
        if ((index5 = index4 - 1) >= 0)
          w[index5] = (int) (uint) (num9 >> 32);
        index1 = index5 + index2;
      }
      ulong num10 = (ulong) (uint) x[0];
      ulong num11 = num10 * num10;
      ulong num12 = num11 >> 32;
      ulong num13 = (num11 & (ulong) uint.MaxValue) + (ulong) (uint) w[index1];
      w[index1] = (int) (uint) num13;
      int index6;
      if ((index6 = index1 - 1) >= 0)
        w[index6] = (int) (uint) (num12 + (num13 >> 32) + (ulong) (uint) w[index6]);
      return w;
    }

    private static int[] Multiply(int[] x, int[] y, int[] z)
    {
      int length = z.Length;
      if (length < 1)
        return x;
      int index1 = x.Length - y.Length;
      long num1;
      while (true)
      {
        long num2 = (long) z[--length] & (long) uint.MaxValue;
        num1 = 0L;
        for (int index2 = y.Length - 1; index2 >= 0; --index2)
        {
          long num3 = num1 + (num2 * ((long) y[index2] & (long) uint.MaxValue) + ((long) x[index1 + index2] & (long) uint.MaxValue));
          x[index1 + index2] = (int) num3;
          num1 = (long) ((ulong) num3 >> 32);
        }
        --index1;
        if (length >= 1)
          x[index1] = (int) num1;
        else
          break;
      }
      if (index1 >= 0)
        x[index1] = (int) num1;
      return x;
    }

    private static long FastExtEuclid(long a, long b, long[] uOut)
    {
      long num1 = 1;
      long num2 = a;
      long num3 = 0;
      long num4;
      for (long index = b; index > 0L; index = num4)
      {
        long num5 = num2 / index;
        long num6 = num1 - num3 * num5;
        num1 = num3;
        num3 = num6;
        num4 = num2 - index * num5;
        num2 = index;
      }
      uOut[0] = num1;
      uOut[1] = (num2 - num1 * a) / b;
      return num2;
    }

    private static long FastModInverse(long v, long m)
    {
      if (m < 1L)
        throw new ArithmeticException("Modulus must be positive");
      long[] uOut = new long[2];
      if (BigInteger.FastExtEuclid(v, m, uOut) != 1L)
        throw new ArithmeticException("Numbers not relatively prime.");
      if (uOut[0] < 0L)
        uOut[0] += m;
      return uOut[0];
    }

    private long GetMQuote()
    {
      if (this.mQuote != -1L)
        return this.mQuote;
      if (this.magnitude.Length == 0 || (this.magnitude[this.magnitude.Length - 1] & 1) == 0)
        return -1;
      this.mQuote = BigInteger.FastModInverse((long) (~this.magnitude[this.magnitude.Length - 1] | 1) & (long) uint.MaxValue, 4294967296L);
      return this.mQuote;
    }

    private static void MultiplyMonty(int[] a, int[] x, int[] y, int[] m, long mQuote)
    {
      if (m.Length == 1)
      {
        x[0] = (int) BigInteger.MultiplyMontyNIsOne((uint) x[0], (uint) y[0], (uint) m[0], (ulong) mQuote);
      }
      else
      {
        int length = m.Length;
        int index1 = length - 1;
        long num1 = (long) y[index1] & (long) uint.MaxValue;
        Array.Clear((Array) a, 0, length + 1);
        for (int index2 = length; index2 > 0; --index2)
        {
          long num2 = (long) x[index2 - 1] & (long) uint.MaxValue;
          long num3 = (((long) a[length] & (long) uint.MaxValue) + (num2 * num1 & (long) uint.MaxValue) & (long) uint.MaxValue) * mQuote & (long) uint.MaxValue;
          long num4 = num2 * num1;
          long num5 = num3 * ((long) m[index1] & (long) uint.MaxValue);
          long num6 = ((long) a[length] & (long) uint.MaxValue) + (num4 & (long) uint.MaxValue) + (num5 & (long) uint.MaxValue);
          long num7 = (long) ((ulong) num4 >> 32) + (long) ((ulong) num5 >> 32) + (long) ((ulong) num6 >> 32);
          for (int index3 = index1; index3 > 0; --index3)
          {
            long num8 = num2 * ((long) y[index3 - 1] & (long) uint.MaxValue);
            long num9 = num3 * ((long) m[index3 - 1] & (long) uint.MaxValue);
            long num10 = ((long) a[index3] & (long) uint.MaxValue) + (num8 & (long) uint.MaxValue) + (num9 & (long) uint.MaxValue) + (num7 & (long) uint.MaxValue);
            num7 = (long) ((ulong) num7 >> 32) + (long) ((ulong) num8 >> 32) + (long) ((ulong) num9 >> 32) + (long) ((ulong) num10 >> 32);
            a[index3 + 1] = (int) num10;
          }
          long num11 = num7 + ((long) a[0] & (long) uint.MaxValue);
          a[1] = (int) num11;
          a[0] = (int) ((ulong) num11 >> 32);
        }
        if (BigInteger.CompareTo(0, a, 0, m) >= 0)
          BigInteger.Subtract(0, a, 0, m);
        Array.Copy((Array) a, 1, (Array) x, 0, length);
      }
    }

    private static uint MultiplyMontyNIsOne(uint x, uint y, uint m, ulong mQuote)
    {
      ulong num1 = (ulong) m;
      long num2 = (long) x * (long) y;
      ulong num3 = ((ulong) num2 * mQuote & BigInteger.UIMASK) * num1;
      ulong num4 = (ulong) ((num2 & (long) BigInteger.UIMASK) + ((long) num3 & (long) BigInteger.UIMASK));
      ulong num5 = ((ulong) num2 >> 32) + (num3 >> 32) + (num4 >> 32);
      if (num5 > num1)
        num5 -= num1;
      return (uint) (num5 & BigInteger.UIMASK);
    }

    public BigInteger Multiply(BigInteger val)
    {
      if (this.sign == 0 || val.sign == 0)
        return BigInteger.Zero;
      if (val.QuickPow2Check())
      {
        BigInteger bigInteger = this.ShiftLeft(val.Abs().BitLength - 1);
        return val.sign <= 0 ? bigInteger.Negate() : bigInteger;
      }
      if (this.QuickPow2Check())
      {
        BigInteger bigInteger = val.ShiftLeft(this.Abs().BitLength - 1);
        return this.sign <= 0 ? bigInteger.Negate() : bigInteger;
      }
      int[] numArray = new int[(this.BitLength + val.BitLength) / 32 + 1];
      if (val == this)
        BigInteger.Square(numArray, this.magnitude);
      else
        BigInteger.Multiply(numArray, this.magnitude, val.magnitude);
      return new BigInteger(this.sign * val.sign, numArray, true);
    }

    public BigInteger Negate() => this.sign == 0 ? this : new BigInteger(-this.sign, this.magnitude, false);

    public BigInteger NextProbablePrime()
    {
      if (this.sign < 0)
        throw new ArithmeticException("Cannot be called on value < 0");
      if (this.CompareTo(BigInteger.Two) < 0)
        return BigInteger.Two;
      BigInteger bigInteger = this.Inc().SetBit(0);
      while (!bigInteger.CheckProbablePrime(100, BigInteger.RandomSource))
        bigInteger = bigInteger.Add(BigInteger.Two);
      return bigInteger;
    }

    public BigInteger Not() => this.Inc().Negate();

    public BigInteger Pow(int exp)
    {
      if (exp < 0)
        throw new ArithmeticException("Negative exponent");
      if (exp == 0)
        return BigInteger.One;
      if (this.sign == 0 || this.Equals((object) BigInteger.One))
        return this;
      BigInteger bigInteger = BigInteger.One;
      BigInteger val = this;
      while (true)
      {
        if ((exp & 1) == 1)
          bigInteger = bigInteger.Multiply(val);
        exp >>= 1;
        if (exp != 0)
          val = val.Multiply(val);
        else
          break;
      }
      return bigInteger;
    }

    public static BigInteger ProbablePrime(int bitLength, Random random) => new BigInteger(bitLength, 100, random);

    private int Remainder(int m)
    {
      long num1 = 0;
      for (int index = 0; index < this.magnitude.Length; ++index)
      {
        long num2 = (long) (uint) this.magnitude[index];
        num1 = (num1 << 32 | num2) % (long) m;
      }
      return (int) num1;
    }

    private int[] Remainder(int[] x, int[] y)
    {
      int index1 = 0;
      while (index1 < x.Length && x[index1] == 0)
        ++index1;
      int index2 = 0;
      while (index2 < y.Length && y[index2] == 0)
        ++index2;
      int num1 = BigInteger.CompareNoLeadingZeroes(index1, x, index2, y);
      if (num1 > 0)
      {
        int num2 = this.calcBitLength(index2, y);
        int num3 = this.calcBitLength(index1, x);
        int n1 = num3 - num2;
        int index3 = 0;
        int num4 = num2;
        int[] numArray;
        if (n1 > 0)
        {
          numArray = BigInteger.ShiftLeft(y, n1);
          num4 += n1;
        }
        else
        {
          int length = y.Length - index2;
          numArray = new int[length];
          Array.Copy((Array) y, index2, (Array) numArray, 0, length);
        }
label_10:
        if (num4 < num3 || BigInteger.CompareNoLeadingZeroes(index1, x, index3, numArray) >= 0)
        {
          BigInteger.Subtract(index1, x, index3, numArray);
          while (x[index1] == 0)
          {
            if (++index1 == x.Length)
              return x;
          }
          num3 = 32 * (x.Length - index1 - 1) + BigInteger.BitLen(x[index1]);
          if (num3 <= num2)
          {
            if (num3 < num2)
              return x;
            num1 = BigInteger.CompareNoLeadingZeroes(index1, x, index2, y);
            if (num1 <= 0)
              goto label_26;
          }
        }
        int n2 = num4 - num3;
        if (n2 == 1 && (uint) numArray[index3] >> 1 > (uint) x[index1])
          ++n2;
        if (n2 < 2)
        {
          BigInteger.ShiftRightOneInPlace(index3, numArray);
          --num4;
        }
        else
        {
          BigInteger.ShiftRightInPlace(index3, numArray, n2);
          num4 -= n2;
        }
        while (numArray[index3] == 0)
          ++index3;
        goto label_10;
      }
label_26:
      if (num1 == 0)
        Array.Clear((Array) x, index1, x.Length - index1);
      return x;
    }

    public BigInteger Remainder(BigInteger n)
    {
      if (n.sign == 0)
        throw new ArithmeticException("Division by zero error");
      if (this.sign == 0)
        return BigInteger.Zero;
      if (n.magnitude.Length == 1)
      {
        int m = n.magnitude[0];
        if (m > 0)
        {
          if (m == 1)
            return BigInteger.Zero;
          int num = this.Remainder(m);
          if (num == 0)
            return BigInteger.Zero;
          return new BigInteger(this.sign, new int[1]
          {
            num
          }, false);
        }
      }
      return BigInteger.CompareNoLeadingZeroes(0, this.magnitude, 0, n.magnitude) < 0 ? this : new BigInteger(this.sign, !n.QuickPow2Check() ? this.Remainder((int[]) this.magnitude.Clone(), n.magnitude) : this.LastNBits(n.Abs().BitLength - 1), true);
    }

    private int[] LastNBits(int n)
    {
      if (n < 1)
        return BigInteger.ZeroMagnitude;
      int length = Math.Min((n + 32 - 1) / 32, this.magnitude.Length);
      int[] destinationArray = new int[length];
      Array.Copy((Array) this.magnitude, this.magnitude.Length - length, (Array) destinationArray, 0, length);
      int num = n % 32;
      if (num != 0)
        destinationArray[0] &= ~(-1 << num);
      return destinationArray;
    }

    private static int[] ShiftLeft(int[] mag, int n)
    {
      int num1 = (int) ((uint) n >> 5);
      int num2 = n & 31;
      int length = mag.Length;
      int[] numArray;
      if (num2 == 0)
      {
        numArray = new int[length + num1];
        mag.CopyTo((Array) numArray, 0);
      }
      else
      {
        int index1 = 0;
        int num3 = 32 - num2;
        int num4 = (int) ((uint) mag[0] >> num3);
        if (num4 != 0)
        {
          numArray = new int[length + num1 + 1];
          numArray[index1++] = num4;
        }
        else
          numArray = new int[length + num1];
        int num5 = mag[0];
        for (int index2 = 0; index2 < length - 1; ++index2)
        {
          int num6 = mag[index2 + 1];
          numArray[index1++] = num5 << num2 | (int) ((uint) num6 >> num3);
          num5 = num6;
        }
        numArray[index1] = mag[length - 1] << num2;
      }
      return numArray;
    }

    public BigInteger ShiftLeft(int n)
    {
      if (this.sign == 0 || this.magnitude.Length == 0)
        return BigInteger.Zero;
      if (n == 0)
        return this;
      if (n < 0)
        return this.ShiftRight(-n);
      BigInteger bigInteger = new BigInteger(this.sign, BigInteger.ShiftLeft(this.magnitude, n), true);
      if (this.nBits != -1)
        bigInteger.nBits = this.sign > 0 ? this.nBits : this.nBits + n;
      if (this.nBitLength != -1)
        bigInteger.nBitLength = this.nBitLength + n;
      return bigInteger;
    }

    private static void ShiftRightInPlace(int start, int[] mag, int n)
    {
      int index1 = (int) ((uint) n >> 5) + start;
      int num1 = n & 31;
      int index2 = mag.Length - 1;
      if (index1 != start)
      {
        int num2 = index1 - start;
        for (int index3 = index2; index3 >= index1; --index3)
          mag[index3] = mag[index3 - num2];
        for (int index4 = index1 - 1; index4 >= start; --index4)
          mag[index4] = 0;
      }
      if (num1 == 0)
        return;
      int num3 = 32 - num1;
      int num4 = mag[index2];
      for (int index5 = index2; index5 > index1; --index5)
      {
        int num5 = mag[index5 - 1];
        mag[index5] = (int) ((uint) num4 >> num1) | num5 << num3;
        num4 = num5;
      }
      mag[index1] = (int) ((uint) mag[index1] >> num1);
    }

    private static void ShiftRightOneInPlace(int start, int[] mag)
    {
      int length = mag.Length;
      int num1 = mag[length - 1];
      while (--length > start)
      {
        int num2 = mag[length - 1];
        mag[length] = (int) ((uint) num1 >> 1) | num2 << 31;
        num1 = num2;
      }
      mag[start] = (int) ((uint) mag[start] >> 1);
    }

    public BigInteger ShiftRight(int n)
    {
      if (n == 0)
        return this;
      if (n < 0)
        return this.ShiftLeft(-n);
      if (n >= this.BitLength)
        return this.sign >= 0 ? BigInteger.Zero : BigInteger.One.Negate();
      int length = this.BitLength - n + 31 >> 5;
      int[] numArray = new int[length];
      int num1 = n >> 5;
      int num2 = n & 31;
      if (num2 == 0)
      {
        Array.Copy((Array) this.magnitude, 0, (Array) numArray, 0, numArray.Length);
      }
      else
      {
        int num3 = 32 - num2;
        int index1 = this.magnitude.Length - 1 - num1;
        for (int index2 = length - 1; index2 >= 0; --index2)
        {
          numArray[index2] = (int) ((uint) this.magnitude[index1--] >> num2);
          if (index1 >= 0)
            numArray[index2] |= this.magnitude[index1] << num3;
        }
      }
      return new BigInteger(this.sign, numArray, false);
    }

    public int SignValue => this.sign;

    private static int[] Subtract(int xStart, int[] x, int yStart, int[] y)
    {
      int length1 = x.Length;
      int length2 = y.Length;
      int num1 = 0;
      do
      {
        long num2 = ((long) x[--length1] & (long) uint.MaxValue) - ((long) y[--length2] & (long) uint.MaxValue) + (long) num1;
        x[length1] = (int) num2;
        num1 = (int) (num2 >> 63);
      }
      while (length2 > yStart);
      if (num1 != 0)
      {
        while (--x[--length1] == -1)
          ;
      }
      return x;
    }

    public BigInteger Subtract(BigInteger n)
    {
      if (n.sign == 0)
        return this;
      if (this.sign == 0)
        return n.Negate();
      if (this.sign != n.sign)
        return this.Add(n.Negate());
      int num = BigInteger.CompareNoLeadingZeroes(0, this.magnitude, 0, n.magnitude);
      if (num == 0)
        return BigInteger.Zero;
      BigInteger bigInteger1;
      BigInteger bigInteger2;
      if (num < 0)
      {
        bigInteger1 = n;
        bigInteger2 = this;
      }
      else
      {
        bigInteger1 = this;
        bigInteger2 = n;
      }
      return new BigInteger(this.sign * num, BigInteger.doSubBigLil(bigInteger1.magnitude, bigInteger2.magnitude), true);
    }

    private static int[] doSubBigLil(int[] bigMag, int[] lilMag) => BigInteger.Subtract(0, (int[]) bigMag.Clone(), 0, lilMag);

    public byte[] ToByteArray() => this.ToByteArray(false);

    public byte[] ToByteArrayUnsigned() => this.ToByteArray(true);

    private byte[] ToByteArray(bool unsigned)
    {
      if (this.sign == 0)
        return !unsigned ? new byte[1] : BigInteger.ZeroEncoding;
      byte[] byteArray = new byte[BigInteger.GetByteLength(!unsigned || this.sign <= 0 ? this.BitLength + 1 : this.BitLength)];
      int length = this.magnitude.Length;
      int num1 = byteArray.Length;
      int num2;
      if (this.sign > 0)
      {
        while (length > 1)
        {
          uint num3 = (uint) this.magnitude[--length];
          int num4;
          byteArray[num4 = num1 - 1] = (byte) num3;
          int num5;
          byteArray[num5 = num4 - 1] = (byte) (num3 >> 8);
          int num6;
          byteArray[num6 = num5 - 1] = (byte) (num3 >> 16);
          byteArray[num1 = num6 - 1] = (byte) (num3 >> 24);
        }
        uint num7;
        for (num7 = (uint) this.magnitude[0]; num7 > (uint) byte.MaxValue; num7 >>= 8)
          byteArray[--num1] = (byte) num7;
        byteArray[num2 = num1 - 1] = (byte) num7;
      }
      else
      {
        bool flag = true;
        while (length > 1)
        {
          uint num8 = (uint) ~this.magnitude[--length];
          if (flag)
            flag = ++num8 == 0U;
          int num9;
          byteArray[num9 = num1 - 1] = (byte) num8;
          int num10;
          byteArray[num10 = num9 - 1] = (byte) (num8 >> 8);
          int num11;
          byteArray[num11 = num10 - 1] = (byte) (num8 >> 16);
          byteArray[num1 = num11 - 1] = (byte) (num8 >> 24);
        }
        uint num12 = (uint) this.magnitude[0];
        if (flag)
          --num12;
        for (; num12 > (uint) byte.MaxValue; num12 >>= 8)
          byteArray[--num1] = (byte) ~num12;
        int num13;
        byteArray[num13 = num1 - 1] = (byte) ~num12;
        if (num13 > 0)
          byteArray[num2 = num13 - 1] = byte.MaxValue;
      }
      return byteArray;
    }

    public override string ToString() => this.ToString(10);

    public string ToString(int radix)
    {
      if (radix != 2 && radix != 10 && radix != 16)
        throw new FormatException("Only bases 2, 10, 16 are allowed");
      if (this.magnitude == null)
        return "null";
      if (this.sign == 0)
        return "0";
      StringBuilder stringBuilder = new StringBuilder();
      switch (radix)
      {
        case 2:
          stringBuilder.Append('1');
          for (int n = this.BitLength - 2; n >= 0; --n)
            stringBuilder.Append(this.TestBit(n) ? '1' : '0');
          break;
        case 16:
          stringBuilder.Append(this.magnitude[0].ToString("x"));
          for (int index = 1; index < this.magnitude.Length; ++index)
            stringBuilder.Append(this.magnitude[index].ToString("x8"));
          break;
        default:
          IList list = (IList) new List<object>();
          BigInteger bigInteger1 = BigInteger.ValueOf((long) radix);
          for (BigInteger bigInteger2 = this.Abs(); bigInteger2.sign != 0; bigInteger2 = bigInteger2.Divide(bigInteger1))
          {
            BigInteger bigInteger3 = bigInteger2.Mod(bigInteger1);
            if (bigInteger3.sign == 0)
              list.Add((object) "0");
            else
              list.Add((object) bigInteger3.magnitude[0].ToString("d"));
          }
          for (int index = list.Count - 1; index >= 0; --index)
            stringBuilder.Append((string) list[index]);
          break;
      }
      string str = stringBuilder.ToString();
      if (str[0] == '0')
      {
        int startIndex = 0;
        do
          ;
        while (str[++startIndex] == '0');
        str = str.Substring(startIndex);
      }
      if (this.sign == -1)
        str = "-" + str;
      return str;
    }

    private static BigInteger createUValueOf(ulong value)
    {
      int num1 = (int) (value >> 32);
      int num2 = (int) value;
      if (num1 != 0)
        return new BigInteger(1, new int[2]
        {
          num1,
          num2
        }, false);
      if (num2 == 0)
        return BigInteger.Zero;
      BigInteger uvalueOf = new BigInteger(1, new int[1]
      {
        num2
      }, false);
      if ((num2 & -num2) == num2)
        uvalueOf.nBits = 1;
      return uvalueOf;
    }

    private static BigInteger createValueOf(long value)
    {
      if (value >= 0L)
        return BigInteger.createUValueOf((ulong) value);
      return value == long.MinValue ? BigInteger.createValueOf(~value).Not() : BigInteger.createValueOf(-value).Negate();
    }

    public static BigInteger ValueOf(long value)
    {
      switch (value)
      {
        case 0:
          return BigInteger.Zero;
        case 1:
          return BigInteger.One;
        case 2:
          return BigInteger.Two;
        case 3:
          return BigInteger.Three;
        default:
          return value == 10L ? BigInteger.Ten : BigInteger.createValueOf(value);
      }
    }

    public int GetLowestSetBit()
    {
      if (this.sign == 0)
        return -1;
      int length = this.magnitude.Length;
      do
        ;
      while (--length > 0 && this.magnitude[length] == 0);
      int num1 = this.magnitude[length];
      int num2 = (num1 & (int) ushort.MaxValue) == 0 ? ((num1 & 16711680) == 0 ? 7 : 15) : ((num1 & (int) byte.MaxValue) == 0 ? 23 : 31);
      while (num2 > 0 && num1 << num2 != int.MinValue)
        --num2;
      return (this.magnitude.Length - length) * 32 - (num2 + 1);
    }

    public bool TestBit(int n)
    {
      if (n < 0)
        throw new ArithmeticException("Bit position must not be negative");
      if (this.sign < 0)
        return !this.Not().TestBit(n);
      int num = n / 32;
      return num < this.magnitude.Length && (this.magnitude[this.magnitude.Length - 1 - num] >> n % 32 & 1) > 0;
    }

    public BigInteger Or(BigInteger value)
    {
      if (this.sign == 0)
        return value;
      if (value.sign == 0)
        return this;
      int[] numArray1 = this.sign > 0 ? this.magnitude : this.Add(BigInteger.One).magnitude;
      int[] numArray2 = value.sign > 0 ? value.magnitude : value.Add(BigInteger.One).magnitude;
      bool flag = this.sign < 0 || value.sign < 0;
      int[] mag = new int[Math.Max(numArray1.Length, numArray2.Length)];
      int num1 = mag.Length - numArray1.Length;
      int num2 = mag.Length - numArray2.Length;
      for (int index = 0; index < mag.Length; ++index)
      {
        int num3 = index >= num1 ? numArray1[index - num1] : 0;
        int num4 = index >= num2 ? numArray2[index - num2] : 0;
        if (this.sign < 0)
          num3 = ~num3;
        if (value.sign < 0)
          num4 = ~num4;
        mag[index] = num3 | num4;
        if (flag)
          mag[index] = ~mag[index];
      }
      BigInteger bigInteger = new BigInteger(1, mag, true);
      if (flag)
        bigInteger = bigInteger.Not();
      return bigInteger;
    }

    public BigInteger Xor(BigInteger value)
    {
      if (this.sign == 0)
        return value;
      if (value.sign == 0)
        return this;
      int[] numArray1 = this.sign > 0 ? this.magnitude : this.Add(BigInteger.One).magnitude;
      int[] numArray2 = value.sign > 0 ? value.magnitude : value.Add(BigInteger.One).magnitude;
      bool flag = this.sign < 0 && value.sign >= 0 || this.sign >= 0 && value.sign < 0;
      int[] mag = new int[Math.Max(numArray1.Length, numArray2.Length)];
      int num1 = mag.Length - numArray1.Length;
      int num2 = mag.Length - numArray2.Length;
      for (int index = 0; index < mag.Length; ++index)
      {
        int num3 = index >= num1 ? numArray1[index - num1] : 0;
        int num4 = index >= num2 ? numArray2[index - num2] : 0;
        if (this.sign < 0)
          num3 = ~num3;
        if (value.sign < 0)
          num4 = ~num4;
        mag[index] = num3 ^ num4;
        if (flag)
          mag[index] = ~mag[index];
      }
      BigInteger bigInteger = new BigInteger(1, mag, true);
      if (flag)
        bigInteger = bigInteger.Not();
      return bigInteger;
    }

    public BigInteger SetBit(int n)
    {
      if (n < 0)
        throw new ArithmeticException("Bit address less than zero");
      if (this.TestBit(n))
        return this;
      return this.sign > 0 && n < this.BitLength - 1 ? this.FlipExistingBit(n) : this.Or(BigInteger.One.ShiftLeft(n));
    }

    public BigInteger ClearBit(int n)
    {
      if (n < 0)
        throw new ArithmeticException("Bit address less than zero");
      if (!this.TestBit(n))
        return this;
      return this.sign > 0 && n < this.BitLength - 1 ? this.FlipExistingBit(n) : this.AndNot(BigInteger.One.ShiftLeft(n));
    }

    public BigInteger FlipBit(int n)
    {
      if (n < 0)
        throw new ArithmeticException("Bit address less than zero");
      return this.sign > 0 && n < this.BitLength - 1 ? this.FlipExistingBit(n) : this.Xor(BigInteger.One.ShiftLeft(n));
    }

    private BigInteger FlipExistingBit(int n)
    {
      int[] mag = (int[]) this.magnitude.Clone();
      mag[mag.Length - 1 - (n >> 5)] ^= 1 << n;
      return new BigInteger(this.sign, mag, false);
    }
  }
}
