using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower().Replace(" ", "");
            cipherText = cipherText.Replace(" ", "");
            int key = 1;

            for (; key < plainText.Length; key++)
            {
                string testCipher = Encrypt(plainText, key);

                bool isequal = true; // Set to true before the loop starts

                for (int i = 0; i < cipherText.Length; i++)
                {
                    if (cipherText[i] != testCipher[i])
                    {
                        isequal = false;
                        break;
                    }
                }

                if (isequal)
                {
                    return key;
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, int key)
        {

            cipherText = cipherText.ToLower().Replace(" ", "");

            int lengthOfCipher = cipherText.Length;
            int col = 0;

            if (lengthOfCipher % key != 0)
            {
                col = (lengthOfCipher / key);
                col += 1;
            }
            else
            {
                col = (lengthOfCipher / key);
            }

            if ((col * key != lengthOfCipher))
            {
                int l = ((col * key) - lengthOfCipher);
                for (int i = 0; i < l; i++)
                {
                    cipherText += " ";
                }
            }

            int index = 0;
            char[,] arr = new char[key, col];
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    arr[i, j] = cipherText[index];
                    index++;
                }
            }

            string plainText = string.Empty;
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    plainText += arr[j, i];
                }
            }
            plainText = plainText.Replace(" ", "");
            return plainText.ToLower();
        }


        public string Encrypt(string plainText, int key)
        {

            plainText = plainText.ToLower().Replace(" ", "");
            int lengthOfPlain = plainText.Length;
            int col = 0;

            if (lengthOfPlain % key != 0)
            {
                col = (lengthOfPlain / key);
                col += 1;
            }
            else
            {
                col = (lengthOfPlain / key);
            }

            if ((col * key != lengthOfPlain))
            {
                int l = ((col * key) - lengthOfPlain);
                for (int i = 0; i < l; i++)
                {
                    plainText += " ";
                }
            }

            int index = 0;
            char[,] arr = new char[key, col];
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    arr[j, i] = plainText[index];
                    index++;
                }
            }

            string cipherText = string.Empty;
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    cipherText += arr[i, j];
                }
            }
            cipherText = cipherText.Replace(" ", "");
            return cipherText.ToUpper();
        }

    }
}
