using System;

namespace Abdt.Babdt.TlSharp.MTProto.Crypto
{
  public class Factorizator
  {
    public static Random random = new Random();

    public static long findSmallMultiplierLopatin(long what)
    {
      long val2 = 0;
      for (int index1 = 0; index1 < 3; ++index1)
      {
        int num1 = (Factorizator.random.Next(128) & 15) + 17;
        long num2 = (long) (Factorizator.random.Next(1000000000) + 1);
        long num3 = num2;
        int num4 = 1 << index1 + 18;
        for (int index2 = 1; index2 < num4; ++index2)
        {
          long num5 = num2;
          long num6 = num2;
          long num7 = (long) num1;
          for (; num6 != 0L; num6 >>= 1)
          {
            if ((num6 & 1L) != 0L)
            {
              num7 += num5;
              if (num7 >= what)
                num7 -= what;
            }
            num5 += num5;
            if (num5 >= what)
              num5 -= what;
          }
          num2 = num7;
          val2 = Factorizator.GCD(num2 < num3 ? num3 - num2 : num2 - num3, what);
          if (val2 == 1L)
          {
            if ((index2 & index2 - 1) == 0)
              num3 = num2;
          }
          else
            break;
        }
        if (val2 > 1L)
          break;
      }
      return Math.Min(what / val2, val2);
    }

    public static long GCD(long a, long b)
    {
      while (a != 0L && b != 0L)
      {
        while ((b & 1L) == 0L)
          b >>= 1;
        while ((a & 1L) == 0L)
          a >>= 1;
        if (a > b)
          a -= b;
        else
          b -= a;
      }
      return b != 0L ? b : a;
    }

    public static FactorizedPair Factorize(BigInteger pq)
    {
      long what = pq.BitLength < 64 ? pq.LongValue : throw new InvalidOperationException("pq too long; TODO: port the pollard algo");
      long multiplierLopatin = Factorizator.findSmallMultiplierLopatin(what);
      return new FactorizedPair(BigInteger.ValueOf(multiplierLopatin), BigInteger.ValueOf(what / multiplierLopatin));
    }
  }
}
