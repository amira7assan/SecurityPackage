using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int ya = Power(alpha, xa, q);
            int yb = Power(alpha, xb, q);

            int ka = Power(yb, xa, q);
            int kb = Power(ya, xb, q);

            List<int> result = new List<int>
            {
                ka,
                kb
            };

            return result;
        }


        public int Power(int num1, int num2, int num3)
        {
            int item = 1;
            for (int i = 0; i < num2; i++)
            {
                item = (item * num1) % num3;
            }
            return item;
        }
    }
}
