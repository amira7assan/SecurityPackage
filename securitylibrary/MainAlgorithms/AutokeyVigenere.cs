using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string mykey = "";
            for (int i = 0, j = 0; i < plainText.Length && j < cipherText.Length; i++, j++)
            {
                char char1 = plainText[i];
                char char2 = cipherText[j];
                if (char.IsLetter(char1) && char.IsLetter(char2))
                {
                    char diff = (char)(((char.ToLower(char2) - 'a') - (char.ToLower(char1) - 'a') + 26) % 26 + 'a');
                    mykey += diff;
                }
            }
            char[] resultChars = new char[mykey.Length];
            int index = 0;
            char[] Cmykey = mykey.ToCharArray();
            char[] Cplain = plainText.ToCharArray();
            for (int i = 0; i < mykey.Length; i++)
            {
                if (index < plainText.Length && Cmykey[i] == Cplain[index])
                {
                    index++;
                }
                else
                {
                    resultChars[i - index] = Cmykey[i];
                }
            }
            string result = new string(resultChars);

            return result;
        }
        public string Decrypt(string cipherText, string key)
        {
            string englishalpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string upperKey = key.ToUpper();
            string upperCipherText = cipherText.ToUpper();
            string decryptedText = "";

            for (int i = 0; i < upperCipherText.Length; i++)
            {
                int cipherIndex = englishalpha.IndexOf(upperCipherText[i]);
                int keyIndex = englishalpha.IndexOf(upperKey[i % upperKey.Length]);
                int decryptedIndex = (cipherIndex - keyIndex + 26) % 26;

                decryptedText += englishalpha[decryptedIndex];
                upperKey += englishalpha[decryptedIndex];
            }

            return decryptedText.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            string combinedKey = key + plainText;

            if (combinedKey.Length > plainText.Length)
            {
                combinedKey = combinedKey.Substring(0, plainText.Length);
            }
            //string repeatedInput2 = RepeatString(key, longP_T);
            string result = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                char char1 = plainText[i];
                char char2 = combinedKey[i % combinedKey.Length];
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
    }
}
