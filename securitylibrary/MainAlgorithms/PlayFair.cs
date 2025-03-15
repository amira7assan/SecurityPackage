using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        public string Encrypt(string plainText, string key)
        {

            plainText = plainText.ToLower().Replace("j", "i").Replace(" ", "");
            key = key.ToLower().Replace("J", "I").Replace(" ", "");
            string modifiedPlainText = plainText;

            // key = abbcccdef ----> newKey = abcdef !!
            string newKey = RemoveOccurrence(key);

            // to add on key the other letters on alphabet that isn't in key 
            // abcdef -----> "abcdefiklmnobq....z"
            string missingLetters=string.Empty;
            string alphabet = "abcdefghiklmnopqrstuvwxyz";
            foreach (char letter in alphabet)
            {
                if (!newKey.Contains(letter))
                {
                    missingLetters += letter;
                }
            }
            newKey+=missingLetters;
            
            // To Fill the newKey into 2D Array [int key matrix];
            char [,] arr = new char[5, 5];
            int index = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    arr[i, j] = newKey[index];
                    index++;
                }
            }
            
            string arrstring = string.Empty;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    arrstring += arr[i, j];
                    
                }
            }

            string cipherText = string.Empty;
            for (int start = 0; start < plainText.Length;)
            {
                char p ;
                char pNext;
                if (start == plainText.Length - 1 || plainText[start] == plainText[start + 1])
                {
                    p     = plainText[start];
                    pNext = 'x';
                    
                }
                else
                {
                    p = modifiedPlainText[start];
                    pNext = modifiedPlainText[start + 1];

                }

                int pI=0, pJ=0;
                int pNextI = 0, pNextJ = 0;

                for(int i = 0;i <5;i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (p == arr[i,j])
                        {
                            pI = i;
                            pJ = j;
                        }

                        if (pNext == arr[i,j])
                        {

                            pNextI = i;
                            pNextJ = j;
                        }
                    }
                }
                // Apply Encryption rules based on character positions
                if (pI ==pNextI)  // in the same row
                {
                    cipherText += arr[pI, (pJ + 1) % 5];
                    cipherText += arr[pNextI, (pNextJ + 1) % 5];
                }
                else if (pJ == pNextJ)  // Same column
                {
                    cipherText += arr[(pI + 1) % 5, pJ];
                    cipherText += arr[(pNextI + 1) % 5, pNextJ];
                }
                else // cross place
                {            
                    cipherText += arr[pI , pNextJ];
                    cipherText += arr[pNextI,pJ];
                }
                if (start != plainText.Length - 1 && plainText[start] == plainText[start + 1])
                    start++;
                else
                    start += 2;

            }

            return cipherText.ToUpper();
            
        }
        


        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower().Replace("j", "i").Replace(" ", "");

            string newKey = RemoveOccurrence(key);
            string missingLetters = string.Empty;

            string alphabet = "abcdefghiklmnopqrstuvwxyz";
            foreach (char letter in alphabet)
            {
                if (!newKey.Contains(letter))
                {
                    missingLetters += letter;
                }
            }
            newKey += missingLetters;

            // to fill key in matrix
            char[,] arr = new char[5, 5];
            int index = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    arr[i, j] = newKey[index];
                    index++;
                }
            }

            string result = string.Empty;
            for (int start = 0; start < cipherText.Length; start += 2) //
            {
                char c1 = cipherText[start];
                char c2 = cipherText[start + 1];
                int cI = 0, cJ = 0;
                int cNextI = 0, cNextJ = 0;


                // Find positions of characters in key matrix
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (c1 == arr[i, j])
                        {
                            cI = i;
                            cJ = j;
                        }
                        if (c2 == arr[i, j])
                        {
                            cNextI = i;
                            cNextJ = j;
                        }
                    }
                }

                // Apply decryption rules based on character positions
                if (cI == cNextI) // Same row
                {
                    if (cJ == 0 && cNextJ > 0)
                    {
                        result += arr[cI, 4];
                        result += arr[cNextI, cNextJ - 1];
                    }
                    if (cNextJ == 0 && cJ > 0)
                    {
                        result += arr[cI, cJ - 1];
                        result += arr[cNextI, 4];
                    }
                    if (cJ > 0 && cNextJ > 0)
                    {
                        result += arr[cI, cJ - 1];
                        result += arr[cNextI, cNextJ - 1];
                    }

                }
                else if (cJ == cNextJ) // Same column
                {
                    if (cI == 0 && cNextI > 0)
                    {
                        result += arr[4, cJ];
                        result += arr[cNextI - 1, cNextJ];
                    }
                    if (cNextI == 0 && cI > 0)
                    {
                        result += arr[cI - 1, cJ];
                        result += arr[4, cNextJ];
                    }
                    if (cI > 0 && cNextI > 0)
                    {
                        result += arr[cI - 1, cJ];
                        result += arr[cNextI - 1, cNextJ];
                    }

                }
                else // Cross place
                {
                    result += arr[cI, cNextJ];
                    result += arr[cNextI, cJ];
                }

            }

            string plainText = string.Empty;
            for (int i = 0; i < result.Length ; i += 2)
            {
                plainText += result[i];
                if (result[i + 1] != 'x')
                {
                    plainText += result[i + 1];
                }
                else if (i + 2 < result.Length && result[i + 1] == 'x' && result[i] != result[i + 2])
                {
                    plainText += result[i + 1];
                }
            }
            return plainText.ToLower();

        }
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }


        /**********************************************************************/
        // helper functions
        static string RemoveOccurrence(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return "";
            }

            StringBuilder sb = new StringBuilder();
            HashSet<char> seenChars = new HashSet<char>();

            foreach (char c in input)
            {
                if (!seenChars.Contains(c))
                {
                    sb.Append(c);
                    seenChars.Add(c);
                }
            }

            return sb.ToString();
        }

    }
}
