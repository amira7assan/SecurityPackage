using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Encrypt(string plainText, string key)
        {
            String cipherText = String.Empty;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (char.IsLetter(plainText[i]))
                {
                    int indexOfIt = plainText[i] - 'a';
                    char tempchar = key[indexOfIt];
                    cipherText = cipherText + tempchar;

                }

            }
            return cipherText;
        }

        public string Decrypt(string cipherText, string key)
        {
            int IndexOfCypherChar;
            string PlainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                IndexOfCypherChar = GetIndexOfCypherChar(cipherText[i], key);
                IndexOfCypherChar = IndexOfCypherChar + 'a';
                PlainText += (char)IndexOfCypherChar;
            }
            return PlainText;
        }

       

        public string Analyse(string plainText, string cipherText)
        {
            char[] alphabet = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
            char[] decryptionKey = new char[26];
            for (int i = 0; i < 26; i++)
                decryptionKey[i] = ' ';

            char[] plaintext = plainText.ToLower().ToCharArray();
            char[] ciphertext = cipherText.ToLower().ToCharArray();
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (plaintext[i] == alphabet[j])
                        decryptionKey[j] = ciphertext[i];
                }
            }

            StringBuilder emptyCharacters = new StringBuilder();
            for (int i = 0; i < 26; i++)
            {
                if (!decryptionKey.Contains(alphabet[i]))
                    emptyCharacters.Append(alphabet[i]);
            }

            int emptyIndex = 0;
            for (int j = 0; j < 26; j++)
            {
                if (decryptionKey[j] == ' ')
                {
                    decryptionKey[j] = emptyCharacters[emptyIndex++];
                }
            }

            string myDecryptionKey = new string(decryptionKey);
            return myDecryptionKey;
        }


        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	=
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        /// 

        public string AnalyseUsingCharFrequency(string cipher)
        {
            string mostFreq = "etaoinsrhldcumfpgwybvkxjqz";
            //string mostFreq = "ETAOINSRHLDCUMFPWYBVKXJQZ";
            List<Tuple<int, char>> Letter = new List<Tuple<int, char>>();
            for (char i = 'A'; i <= 'Z'; i++)
            {
                int count = 0;
                for (int j = 0; j < cipher.Length; j++)
                {
                    if (cipher[j] == i)
                    {
                        count++;
                    }
                    else if (j == cipher.Length - 1)
                    {
                        //for (int s = 0; s < 26; s++)
                        //{

                        Letter.Add(new Tuple<int, char>(count, i));

                        //}
                    }
                    else
                        continue;
                }
            }
            //Letter = (List<Tuple<char, int>>)Letter.OrderBy(t => t.Item2);
            Letter.Sort((x, y) => y.Item1.CompareTo(x.Item1));
            int z = 0;
            List<Tuple<char, char>> key = new List<Tuple<char, char>>();
            for (z = 0; z < Letter.Count; z++)
            {
                key.Add(new Tuple<char, char>(Letter[z].Item2, mostFreq[z]));
            }
            key.Sort((y, x) => y.Item1.CompareTo(x.Item1));
            string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            int count1 = key.Count;

            for (int i = 0; i < 26; i++)
            {

                if (key.Count != 26)
                {
                    if (key[i].Item1 != alpha[i])
                    {
                        key.Insert(i, new Tuple<char, char>(alpha[i], mostFreq[count1]));
                        count1++;
                    }
                }
            }
            char[] PText = new char[cipher.Length];
            for (int j = 0; j < cipher.Length; j++)
            {
                for (int i = 0; i < key.Count; i++)
                {
                    if (cipher[j] == key[i].Item1)
                    {
                        PText[j] = key[i].Item2;
                    }
                    else
                    {
                        continue;
                    }

                }
            }
            string end = "";
            for (int i = 0; i < PText.Length; i++)
            {

                end += PText[i];
            }
            return end;

        }

        /************************************************************************/
        //Helper Functions:
        private int GetIndexOfCypherChar(char c, string key)
        {
            key = key.ToUpper();

            for (int i = 0; i < key.Length; i++)
            {
                if (c == key[i])
                    return i;
            }
            return -1;
        }
    }
}