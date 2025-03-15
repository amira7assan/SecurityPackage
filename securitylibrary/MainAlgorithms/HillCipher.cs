using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public string s = "abcdefghijklmnopqrstuvwxyz";
        static int calculateDetermenantfor2x2matrix(int[,] matrix)
        {
            int a = matrix[0, 0];
            int b = matrix[0, 1];
            int c = matrix[1, 0];
            int d = matrix[1, 1];
            return (a * d - b * c);
        }
        static int[,] inversOf3matrix(int[,] InversMatrix, int[,] oldmatrix, int fac, int size)
        {
            InversMatrix[0, 0] = ((oldmatrix[1, 1] * oldmatrix[2, 2] - oldmatrix[2, 1] * oldmatrix[1, 2]) * fac) % 26;
            InversMatrix[0, 1] = (-(oldmatrix[1, 0] * oldmatrix[2, 2] - oldmatrix[1, 2] * oldmatrix[2, 0]) * fac) % 26;
            InversMatrix[0, 2] = ((oldmatrix[1, 0] * oldmatrix[2, 1] - oldmatrix[2, 0] * oldmatrix[1, 1]) * fac) % 26;

            InversMatrix[1, 0] = (-(oldmatrix[0, 1] * oldmatrix[2, 2] - oldmatrix[0, 2] * oldmatrix[2, 1]) * fac) % 26;
            InversMatrix[1, 1] = ((oldmatrix[0, 0] * oldmatrix[2, 2] - oldmatrix[0, 2] * oldmatrix[2, 0]) * fac) % 26;
            InversMatrix[1, 2] = (-(oldmatrix[0, 0] * oldmatrix[2, 1] - oldmatrix[2, 0] * oldmatrix[0, 1]) * fac) % 26;

            InversMatrix[2, 0] = ((oldmatrix[0, 1] * oldmatrix[1, 2] - oldmatrix[0, 2] * oldmatrix[1, 1]) * fac) % 26;
            InversMatrix[2, 1] = (-(oldmatrix[0, 0] * oldmatrix[1, 2] - oldmatrix[1, 0] * oldmatrix[0, 2]) * fac) % 26;
            InversMatrix[2, 2] = ((oldmatrix[0, 0] * oldmatrix[1, 1] - oldmatrix[1, 0] * oldmatrix[0, 1]) * fac) % 26;
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    if (InversMatrix[i, j] < 0)
                        InversMatrix[i, j] = InversMatrix[i, j] + 26;
                }
            }
            int[,] transpose = new int[3, 3];
            for (int u = 0; u < 3; u++)
                for (int o = 0; o < 3; o++)
                    transpose[o, u] = InversMatrix[u, o];
            return transpose;
        }
        static void getcofactormatrix(int[,] matrix, int[,] submatrix, int n, int x, int y)
        {
            int r = 0, c = 0;
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    if (i != x && j != y)
                    {
                        submatrix[r, c] = matrix[i, j];
                        c++;
                        if (c == n - 1)
                        {
                            c = 0;
                            r++;
                        }
                    }
                    else
                        continue;
                }
            }
        }
        static int calculateDetermenant(int[,] matrix, int n)
        {
            if (n == 1)
                return matrix[0, 0];
            if (n == 2)
                return calculateDetermenantfor2x2matrix(matrix);

            int determenant = 0, sign = 1;
            int[,] submatrix = new int[n - 1, n - 1];

            for (int i = 0; i < n; i++)
            {
                getcofactormatrix(matrix, submatrix, n, 0, i);
                determenant += sign * matrix[0, i] * calculateDetermenant(submatrix, n - 1);
                sign *= -1;
            }
            return determenant;
        }
        static void getmatrixofcofactors(int[,] matrix, int[,] mat, int n)
        {
            if (n == 1)
            {
                mat[0, 0] = 1;
                return;
            }
            int[,] submatrix;
            int sign;
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    submatrix = new int[n - 1, n - 1];
                    getcofactormatrix(matrix, submatrix, n, i, j);
                    if ((i + j) % 2 == 0)
                        sign = 1;
                    else
                        sign = -1;
                    mat[i, j] = (sign) * (calculateDetermenant(submatrix, n - 1));
                }
            }
        }
        static void Transpose(int[,] x, int n)
        {
            int a;
            for (int i = 0; i < n; i++)
            {
                for (int j = i + 1; j < n; j++)
                {
                    a = x[i, j];
                    x[i, j] = x[j, i];
                    x[j, i] = a;
                }
            }
        }
        static int[,] GetKeyMatrix(List<int> key, int n)
        {
            int[,] KeyMatrix = new int[n, n];
            int k = 0;
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    KeyMatrix[i, j] = key[k];
                    k++;
                }
            }
            return KeyMatrix;
        }

        static int[,] GetCipherMatrix(List<int> cipher, int n)
        {
            int m = cipher.Count / n;
            int k = 0;
            int[,] CipherMatrix = new int[n, m];

            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    CipherMatrix[j, i] = cipher[k];
                    k++;
                }
            }
            return CipherMatrix;
        }

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> keys = new List<int>();
            bool flag = false;
            for (int a = 0; a < 26; a++)
            {
                for (int b = 0; b < 26; b++)
                {
                    for (int c = 0; c < 26; c++)
                    {
                        for (int d = 0; d < 26; d++)
                        {
                            if (cipherText[0] == ((b * plainText[0] + a * plainText[1]) % 26) &&
                               cipherText[1] == ((d * plainText[0] + c * plainText[1]) % 26) &&
                               cipherText[2] == ((b * plainText[2] + a * plainText[3]) % 26) &&
                               cipherText[3] == ((d * plainText[2] + c * plainText[3]) % 26))
                            {
                                keys.Add(b);
                                keys.Add(a);
                                keys.Add(d);
                                keys.Add(c);
                                flag = true;
                            }
                            if (flag) break;
                        }
                        if (flag) break;
                    }
                    if (flag) break;
                }
                if (flag) break;
            }
            if (keys.Count == 0) throw new InvalidAnlysisException();
            else
                return keys;
        }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int x = (int)Math.Sqrt(key.Count);

            int[,] KeyMatrix = GetKeyMatrix(key, x);
            int[,] CipherMatrix = GetCipherMatrix(cipherText, x);

            int determinant = calculateDetermenant(KeyMatrix, x);

            while (determinant < 0)
                determinant += 26;

            int b = 0, temp = 0;
            for (int i = 1; i < 26; i++)
            {
                temp = i * determinant;

                if ((temp % 26) == 1)
                {
                    b = i;
                    break;
                }
            }

            int[,] MatrixOfCofactors = new int[x, x];
            getmatrixofcofactors(KeyMatrix, MatrixOfCofactors, x);
            Transpose(MatrixOfCofactors, x);

            if (b != 0)
            {
                for (int i = 0; i < x; i++)
                {
                    for (int j = 0; j < x; j++)
                    {
                        while (MatrixOfCofactors[i, j] < 0)
                            MatrixOfCofactors[i, j] += 26;
                        MatrixOfCofactors[i, j] = (MatrixOfCofactors[i, j] * b) % 26;
                    }
                }
            }
            int y = cipherText.Count / x;
            int[,] product = new int[x, y];
            int sum = 0;

            for (int i = 0; i < x; i++)
            {
                for (int j = 0; j < y; j++)
                {
                    sum = 0;
                    for (int k = 0; k < x; k++)
                        sum += MatrixOfCofactors[i, k] * CipherMatrix[k, j];
                    product[i, j] = sum % 26;
                }
            }
            List<int> plaintext = new List<int> { };
            for (int i = 0; i < y; i++)
            {
                for (int j = 0; j < x; j++)
                    plaintext.Add(product[j, i]);
            }
            return plaintext;
            //throw new NotImplementedException();
        }
        public string Decrypt(string cipherText, string key)
        {
            int k = 0, n = cipherText.Length;
            int row, column;
            row = (int)Math.Floor(Math.Sqrt(n));
            column = (int)Math.Ceiling(Math.Sqrt(n));

            if (row * column < n)
                row = column;

            int[,] cipherindex = new int[row, column];
            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    int t = s.IndexOf(cipherText[k]);
                    cipherindex[j, i] = t;
                    k++;
                }
            }

            int m = (int)Math.Sqrt(key.Length);
            int[,] keymat = new int[m, m];
            k = 0;

            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    int t = s.IndexOf(key[k]);
                    keymat[i, j] = t;
                    k++;
                }
            }
            int determinant = calculateDetermenant(keymat, m);

            while (determinant < 0)
                determinant += 26;

            int b = 0, temp = 0;
            for (int i = 0; i < 26; i++)
            {
                temp = i * determinant;

                if ((temp % 26) == 1)
                {
                    b = i;
                    break;
                }
            }

            int[,] MatrixOfCofactors = new int[m, m];
            getmatrixofcofactors(keymat, MatrixOfCofactors, m);
            Transpose(MatrixOfCofactors, m);

            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    while (MatrixOfCofactors[i, j] < 0)
                        MatrixOfCofactors[i, j] += 26;
                    MatrixOfCofactors[i, j] = (MatrixOfCofactors[i, j] * b) % 26;
                }
            }

            int[,] product = new int[m, column];
            int sum = 0;

            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    sum = 0;
                    for (int x = 0; x < m; x++)
                        sum += MatrixOfCofactors[i, x] * cipherindex[x, j];
                    product[i, j] = sum % 26;
                }
            }

            string plaintext = "";

            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < m; j++)
                    plaintext += s[product[j, i]];
            }
            return plaintext;
            // Decrypt((int)cipherText.ToList(), key.ToList());
            //throw new NotImplementedException();
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int keysize = (int)Math.Sqrt(key.Count);
            int textsize = plainText.Count / keysize;
            List<int> cipher = new List<int> { };
            int[,] ciphermatrix = new int[keysize, textsize];

            int[,] Keymatrix = new int[keysize, keysize];
            int[,] textmatrix = new int[keysize, textsize];

            //fill key matrix
            int keyit = 0;
            for (int i = 0; i < keysize; i++)
            {
                for (int j = 0; j < keysize; j++)
                {
                    Keymatrix[i, j] = key[keyit];
                    keyit++;
                }
            }
            //fill text matrix
            int textit = 0;
            for (int i = 0; i < textsize; i++)
            {
                for (int j = 0; j < keysize; j++)
                {
                    textmatrix[j, i] = plainText[textit];
                    textit++;
                }
            }
            int value = 0;
            for (int i = 0; i < textsize; i++)
            {
                for (int k = 0; k < keysize; k++)
                {
                    for (int j = 0; j < keysize; j++)
                    {

                        value += textmatrix[j, i] * Keymatrix[k, j];

                    }

                    ciphermatrix[k, i] = value % 26;
                    value = 0;
                }
            }

            for (int i = 0; i < textsize; i++)
            {
                for (int j = 0; j < keysize; j++)
                {
                    cipher.Add(ciphermatrix[j, i]);
                }
            }

            return cipher;



        }
        public string Encrypt(string plainText, string key)
        {
            string a_z = "abcdefghijklmnopqrstuvwxyz";
            string newcipher = "";
            List<int> plainlist = new List<int>() { };
            List<int> keylist = new List<int>() { };
            List<int> cipher = new List<int>() { };
            foreach (char c in plainText)
            {
                plainlist.Add(a_z.IndexOf(c));

            }
            foreach (char c in key)
            {
                keylist.Add(a_z.IndexOf(c));

            }

            cipher = Encrypt(plainlist, keylist).ToList();
            foreach (char c in cipher)
            {
                newcipher.Append(c);
            }
            return newcipher.ToString();

        }


        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //listof ciphir and plantext
            int[,] pt = new int[3, 3];
            int[,] ct = new int[3, 3];
            int num = 0;
            for (int k = 0; k < 3; k++)
            {
                for (int j = 0; j < 3; j++)
                {
                    pt[j, k] = plain3[num];
                    ct[j, k] = cipher3[num];
                    num++;
                }
            }
            //determante
            int det = 0;
            int i = 0;
            for (i = 0; i < 3; i++)
                det = det + (pt[0, i] * (pt[1, (i + 1) % 3] * pt[2, (i + 2) % 3] - pt[1, (i + 2) % 3] * pt[2, (i + 1) % 3]) % 26);
            if (det < 0)
                det += 26;
            //factor
            int a = 0;
            for (a = 1; a <= 26; a++)
            {
                if ((a * det) % 26 == 1)
                {
                    break;
                }
            }
            //invers pt 
            int[,] InversM = new int[3, 3];
            InversM = inversOf3matrix(InversM, pt, a, 3);
            //newplan
            List<int> NewPlain = new List<int>();
            for (int k = 0; k < 3; k++)
            {
                for (int j = 0; j < 3; j++)
                {
                    NewPlain.Add(InversM[j, k]);
                }
            }

            //euq fainallly
            List<int> key = new List<int>();
            for (int k = 0; k < 3; k++)
            {
                int e = (ct[k, 0] * NewPlain[0] + ct[k, 1] * NewPlain[1] + ct[k, 2] * NewPlain[2]) % 26;
                int f = (ct[k, 0] * NewPlain[3] + ct[k, 1] * NewPlain[4] + ct[k, 2] * NewPlain[5]) % 26;
                int g = (ct[k, 0] * NewPlain[6] + ct[k, 1] * NewPlain[7] + ct[k, 2] * NewPlain[8]) % 26;
                if (e < 0)
                    e += 26;
                if (f < 0)
                    f += 26;
                if (g < 0)
                    g += 26;
                key.Add(e);
                key.Add(f);
                key.Add(g);
            }
            return key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }



    }
}

