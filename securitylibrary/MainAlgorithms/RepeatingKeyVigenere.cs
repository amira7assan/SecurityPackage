using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string result = "";
            for (int i = 0, j = 0; i < plainText.Length && j < cipherText.Length; i++, j++)
            {
                char char1 = plainText[i];
                char char2 = cipherText[j];
                if (char.IsLetter(char1) && char.IsLetter(char2))
                {
                    char diff = (char)(((char.ToLower(char2) - 'a') - (char.ToLower(char1) - 'a') + 26) % 26 + 'a');
                    result += diff;
                }
            }
            int n = result.Length; //depectedepectedepecte
            int maxLength = 0;
            string longestPattern = "";
            for (int i = 0; i < n; i++)
            {
                for (int j = i + 1; j < n; j++)
                {
                    int len = j - i;
                    if (i + 2 * len <= n && result.Substring(i, len) == result.Substring(i + len, len))
                    {
                        if (len > maxLength)
                        {
                            maxLength = len;
                            longestPattern = result.Substring(i, len);
                        }
                    }
                }
            }
            return longestPattern;
        }

        public string Decrypt(string cipherText, string key)
        {
            int alphabetCount1 = 0;
            int alphabetCount2 = 0;
            foreach (char c in cipherText)
            {
                if (char.IsLetter(c))
                {
                    alphabetCount1++;
                }
            }
            foreach (char c in key)
            {
                if (char.IsLetter(c))
                {
                    alphabetCount2++;
                }
            }
            int longC_T = (alphabetCount1 + alphabetCount2 - 1) / alphabetCount2;
            string repeatedInput2 = RepeatString(key, longC_T);
            string result = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                char char1 = cipherText[i];
                char char2 = repeatedInput2[i % repeatedInput2.Length];
                if (char.IsLetter(char1) && char.IsLetter(char2))
                {
                    // char diff = (char)(((char1 - 'A') - (char2 - 'A') + 26) % 26 + 'A');
                    char diff = (char)(((char.ToLower(char1) - 'A') - (char.ToLower(char2) - 'A') + 26) % 26 + 'A');
                    result += diff;
                }
            }
            return result;
        }

        public string Encrypt(string plainText, string key)
        {
            int alphabetCount1 = 0;
            int alphabetCount2 = 0;
            foreach (char c in plainText)
            {
                if (char.IsLetter(c))
                {
                    alphabetCount1++;
                }
            }
            foreach (char c in key)
            {
                if (char.IsLetter(c))
                {
                    alphabetCount2++;
                }
            }

            // plain 15 , key 3  then long (15+3-1)/3 = 5.6   >>>>> 5.6*3=17   >>>> int 5*3 = 15
            int longP_T = (alphabetCount1 + alphabetCount2 - 1) / alphabetCount2;

            string repeatedInput2 = RepeatString(key, longP_T);
            string result = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                char char1 = plainText[i];
                char char2 = repeatedInput2[i % repeatedInput2.Length];
                if (char.IsLetter(char1) && char.IsLetter(char2))
                {
                    char sum = (char)((char.ToLower(char1) - 'a' + char.ToLower(char2) - 'a') % 26 + 'a');
                    if (char.IsUpper(char1))
                        sum = char.ToUpper(sum);
                    result += sum;
                }
                else
                {
                    result += char1;
                }
            }
            return result;
        }

        static string RepeatString(string str, int times)
        {
            string repeatedString = "";
            for (int i = 0; i < times; i++)
            {
                repeatedString += str;
            }
            return repeatedString;
        }

        //  static string RepeatString(string str, int times)
        //{
        //  StringBuilder repeatedString = new StringBuilder();
        //for (int i = 0; i < times; i++)
        //{
        //  repeatedString.Append(str);
        //}
        //return repeatedString.ToString();
        // }
    }
}
