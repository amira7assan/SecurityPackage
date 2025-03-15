using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> cipherText = new List<long>();

            int x1 = ModPowEnc(alpha, k, q);
            int k2 = ModPowEnc(y, k, q);
            int x2 = (k2 * m) % q;

            cipherText.Add((long)x1);
            cipherText.Add((long)x2);

            return cipherText;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            // Compute the shared secret
            long s = ModPowDEC(c1, x, q);

            // Compute the modular inverse of s
            long sInv = ModInv(s, q);

            // Decrypt the message
            long m = c2 * sInv % q;

            // Return the decrypted message as an integer
            return (int)m;

        }




        /*********************** Helper Functions *************************/
        // for enc
        public static int ModPowEnc(int a, int b, int modulus)
        {
            int result = 1;
            for (int i = 0; i < b; i++)
            {
                // Check if bit is 1 using bitwise AND (optimized for int)
                result = (result * a) % modulus;
            }
            return result;
        }

        /************/
        // For Dec :
        public static long ModPowDEC(long a, long b, long m)
        {
            long result = 1;
            while (b > 0)
            {
                if ((b & 1) == 1)
                {
                    result = result * a % m;
                }
                a = a * a % m;
                b >>= 1;
            }
            return result;
        }

        public static long ModInv(long a, long m)
        {
            long m0 = m, t, q;
            long x0 = 0, x1 = 1;
            if (m == 1)
                return 0;
            while (a > 1)
            {
                // q is quotient
                q = a / m;
                t = m;

                // m is remainder now, process same as Euclid's algo
                m = a % m;
                a = t;

                t = x0;

                x0 = x1 - q * x0;

                x1 = t;
            }
            // Make x1 positive
            if (x1 < 0)
            {
                x1 += m0;
            }

            return x1;
        }
    }




}
