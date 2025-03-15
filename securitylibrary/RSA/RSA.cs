using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;
namespace SecurityLibrary.RSA
{
    public class RSA
    {
        ExtendedEuclid EX = new ExtendedEuclid();
        public static int ModOfPower(int a, int b, int m)
        {
            int x = 1;

            if (b == 0)
                return 1;

            else if (b == 1)
                return a % m;

            else
            {
                for (int i = 0; i < b; i++)
                    x = (x * a) % m;
            }

            return x;
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            int cipher = ModOfPower(M, e, n);
            return cipher;
            //throw new NotImplementedException();
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int Q = (p - 1) * (q - 1);
            int d = EX.GetMultiplicativeInverse(e, (int)Q);
            int PlainText = ModOfPower(C, d, n);
            return PlainText;
            //throw new NotImplementedException();
        }
    }
}
