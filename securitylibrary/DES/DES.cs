using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public string IP_1(string value)
        {

            StringBuilder result = new StringBuilder();
            List<int> IP = new List<int>
        { 40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25,};

            for (int i = 0; i < IP.Count; i++)
            {
                result.Append(value[IP[i] - 1]);

            }



            return result.ToString();
        }



        public string P(string value)
        {

            StringBuilder newafterp = new StringBuilder();
            List<int> P = new List<int>
        {  16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25,};

            for (int i = 0; i < P.Count; i++)
            {
                newafterp.Append(value[P[i] - 1]);

            }



            return newafterp.ToString();
        }

        public string decimaltobinary(int deci)
        {

            Dictionary<string, string> decCharacterToBinary = new Dictionary<string, string> {
                { "0", "0000" },
                { "1", "0001" },
                { "2", "0010" },
                { "3", "0011" },
                { "4", "0100" },
                { "5", "0101" },
                { "6", "0110" },
                { "7", "0111" },
                { "8", "1000" },
                { "9", "1001" },
                { "10", "1010" },
                { "11", "1011" },
                { "12", "1100" },
                { "13", "1101" },
                { "14", "1110" },
                { "15", "1111" }
                                };
            string binary = decCharacterToBinary[deci.ToString()];

            return binary;
        }
        public string convertobinary(string hex)
        {
            StringBuilder binary = new StringBuilder();

            Dictionary<char, string> hexCharacterToBinary = new Dictionary<char, string> {
                { '0', "0000" },
                { '1', "0001" },
                { '2', "0010" },
                { '3', "0011" },
                { '4', "0100" },
                { '5', "0101" },
                { '6', "0110" },
                { '7', "0111" },
                { '8', "1000" },
                { '9', "1001" },
                { 'A', "1010" },
                { 'B', "1011" },
                { 'C', "1100" },
                { 'D', "1101" },
                { 'E', "1110" },
                { 'F', "1111" }
                                };
            for (int i = 2; i < hex.Length; i++)
            {
                binary.Append(hexCharacterToBinary[hex[i]]);

            }

            return binary.ToString();
        }
        public string SBOX(List<string> bit6)
        {

            StringBuilder result = new StringBuilder();



            int[,] S1 = {
            { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
            { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
            { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
            { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
        };
            int[,] S2 = {
            { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
            { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
            { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
            { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
        };
            int[,] S3 = {
            { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
            { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
            { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
            { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
        };
            int[,] S4 = {
            { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
            { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
            { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
            { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
        };
            int[,] S5 = {
            { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
            { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
            { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
            { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
        };
            int[,] S6 = {
            { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
            { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
            { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
            { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
        };
            int[,] S7 = {
            { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
            { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
            { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
            { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
        };
            int[,] S8 = {
            { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
            { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
            { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
            {   2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
        };
            int row = 0;
            int col = 0;

            for (int i = 0; i < bit6.Count; i++)
            {
                string value = bit6[i];
                if (value[0] == '0')
                {
                    if (value[5] == '0')
                    {
                        row = 0;

                    }
                    else
                    {
                        row = 1;

                    }

                }
                else if (value[0] == '1')
                {
                    if (value[5] == '1')
                    {
                        row = 3;

                    }
                    else
                    {
                        row = 2;

                    }
                }
                string inside = value.Substring(1, 4);
                switch (inside)
                {
                    case "0000":
                        col = 0;
                        break;
                    case "0001":
                        col = 1;
                        break;
                    case "0010":
                        col = 2;
                        break;
                    case "0011":
                        col = 3;
                        break;
                    case "0100":
                        col = 4;
                        break;
                    case "0101":
                        col = 5;
                        break;
                    case "0110":
                        col = 6;
                        break;
                    case "0111":
                        col = 7;
                        break;
                    case "1000":
                        col = 8;
                        break;
                    case "1001":
                        col = 9;
                        break;
                    case "1010":
                        col = 10;
                        break;
                    case "1011":
                        col = 11;
                        break;
                    case "1100":
                        col = 12;
                        break;
                    case "1101":
                        col = 13;
                        break;
                    case "1110":
                        col = 14;
                        break;
                    case "1111":
                        col = 15;
                        break;
                }
                int svalue = 0;
                switch (i)
                {
                    case 0:
                        svalue = S1[row, col];
                        break;
                    case 1:
                        svalue = S2[row, col];
                        break;
                    case 2:
                        svalue = S3[row, col];
                        break;
                    case 3:
                        svalue = S4[row, col];
                        break;
                    case 4:
                        svalue = S5[row, col];
                        break;
                    case 5:
                        svalue = S6[row, col];
                        break;
                    case 6:
                        svalue = S7[row, col];
                        break;
                    case 7:
                        svalue = S8[row, col];
                        break;
                }


                result.Append(decimaltobinary(svalue));
            }




            return result.ToString();
        }

        public string XOR(string Text1, string Text2)
        {
            //if (Text1 == "") 
            //    return Text2;

            string Matrix = "";
            for (int i = 0; i < Text1.Length; i++)
            {
                if (Text1[i] == Text2[i])
                {
                    Matrix += '0';
                }
                else
                {
                    Matrix += '1';
                }
            }
            return Matrix;
        }
        public string EBIT(string value)
        {

            StringBuilder newR0 = new StringBuilder();
            List<int> ER0 = new List<int>
        {  32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1,};

            for (int i = 0; i < ER0.Count; i++)
            {
                newR0.Append(value[ER0[i] - 1]);

            }



            return newR0.ToString();
        }

        public string IP(string value)
        {

            StringBuilder newplain = new StringBuilder();
            List<int> IP = new List<int>
        { 58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7,};

            for (int i = 0; i < IP.Count; i++)
            {
                newplain.Append(value[IP[i] - 1]);

            }



            return newplain.ToString();
        }

        public string PC1(string value)
        {

            StringBuilder newkey = new StringBuilder();
            List<int> PC = new List<int>
        {57, 49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,56,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4,};

            for (int i = 0; i < PC.Count; i++)
            {
                newkey.Append(value[PC[i] - 1]);

            }



            return newkey.ToString();
        }


        public List<String> subKey16(string value)
        {

            List<int> shiftamount = new List<int>
        {1,1, 2,2,2,2,2,2,1,2,2,2,2,2,2,1};

            List<string> shiftedvalues = new List<string> { };
            shiftedvalues.Add(value.Substring(0, 28));
            shiftedvalues.Add(value.Substring(28));
            int iterator = 0;
            for (int i = 0; i < 32; i += 2)
            {
                string d1 = shiftedvalues[i].Substring(0, shiftamount[iterator]);
                string temp1 = shiftedvalues[i].Substring(shiftamount[iterator]);
                string valuetoadd1 = temp1 + d1;
                shiftedvalues.Add(valuetoadd1);
                string d2 = shiftedvalues[i + 1].Substring(0, shiftamount[iterator]);
                string temp2 = shiftedvalues[i + 1].Substring(shiftamount[iterator]);
                string valuetoadd2 = temp2 + d2;
                shiftedvalues.Add(valuetoadd2);

                iterator++;

            }



            return shiftedvalues;
        }
        public List<String> concat16key(List<string> value)
        {


            List<string> keys16 = new List<string> { };


            for (int i = 2; i < 34; i += 2)
            {
                string key = value[i] + value[i + 1];
                keys16.Add(key);

            }



            return keys16;
        }

        public List<string> PC2(List<string> value)
        {

            StringBuilder newkey = new StringBuilder();
            List<int> PC = new List<int>
        { 14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32,};

            List<string> newkey16 = new List<string>() { };
            for (int i = 0; i < value.Count; i++)
            {
                for (int j = 0; j < PC.Count; j++)
                {

                    string text = value[i];
                    newkey.Append(text[PC[j] - 1]);


                }
                newkey16.Add(newkey.ToString());
                newkey.Clear();
            }



            return newkey16;
        }
        int[,] matrixpc1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 },
     { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 },
     { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 },
     { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 },
     { 21, 13, 5, 28, 20, 12, 4 } };
        int[,] matrixpc2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 },
     { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 },
     { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 },
     { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 },
     { 46, 42, 50, 36, 29, 32 } };
        int[,] p = new int[8, 4]
            { { 16, 7, 20, 21 }, { 29, 12, 28, 17 },
     { 1, 15, 23, 26 }, { 5, 18, 31, 10 },
     { 2, 8, 24, 14 }, { 32, 27, 3, 9 },
     { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };
        int[,] Ebit = new int[8, 6]
            { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 },
     { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 },
     { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 },
     { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };
        int[,] mip = new int[8, 8]
        { { 58, 50, 42, 34, 26, 18, 10, 2 },{ 60, 52, 44, 36, 28, 20, 12, 4 },
     { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8},
     { 57, 49, 41, 33, 25, 17, 9, 1 },{ 59, 51, 43, 35, 27, 19, 11, 3 },
     { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 }};
        int[,] ipInvers = new int[8, 8]
        { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 },
     { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 },
     { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 },
     { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 }};
        int[,] Sbox1 = new int[4, 16]
          { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
     { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
     { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
     { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
        int[,] Sbox2 = new int[4, 16]
          { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
     { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
     { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
     { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
        int[,] Sbox3 = new int[4, 16]
            { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
     { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
     { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
     { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
        int[,] Sbox4 = new int[4, 16]
           { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
     { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
     { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
     { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
        int[,] Sbox5 = new int[4, 16]
            { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
     { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
     { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
     { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
        int[,] Sbox6 = new int[4, 16]
            { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
     { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
     { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
     { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
        int[,] Sbox7 = new int[4, 16]
            { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
     { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
     { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
     { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
        int[,] Sbox8 = new int[4, 16]
            { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
     { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
     { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
     { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };
        string S1 = "";
        string S2 = "";
        string Temp = "";
        List<string> listforC = new List<string>();
        List<string> listforD = new List<string>();

        public override string Decrypt(string cipherText, string key)
        {
            // Convert hexadecimal input to binary format
            string binaryCipherText = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string binaryKey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            // Lists for keys and intermediate processing
            List<string> roundKeys = GenerateRoundKeys(binaryKey);

            // Initial permutation of the cipher text
            string permutedCipherText = ApplyPermutation(binaryCipherText, mip);

            // Split the permuted cipher text into left and right halves
            string leftHalf = permutedCipherText.Substring(0, 32);
            string rightHalf = permutedCipherText.Substring(32);

            // Process through 16 rounds in reverse order (decryption)
            for (int round = 15; round >= 0; round--)
            {
                string currentRoundKey = roundKeys[round];
                string newRightHalf = PerformDESRound(rightHalf, currentRoundKey, leftHalf);

                // Shift left half to the right and use the new right half
                leftHalf = rightHalf;
                rightHalf = newRightHalf;
            }

            // Combine final left and right halves
            string finalOutput = rightHalf + leftHalf;

            // Apply inverse permutation to get the decrypted binary
            string decryptedBinary = ApplyPermutation(finalOutput, ipInvers);

            // Convert binary to hexadecimal format
            string decryptedHex = "0x" + Convert.ToInt64(decryptedBinary, 2).ToString("X").PadLeft(16, '0');

            return decryptedHex;
        }

        // Function to generate round keys
        private List<string> GenerateRoundKeys(string binaryKey)
        {
            List<string> roundKeys = new List<string>();

            // Initial key permutation
            string permutedKey = ApplyPermutation(binaryKey, matrixpc1);

            // Split permuted key into two halves
            string leftKey = permutedKey.Substring(0, 28);
            string rightKey = permutedKey.Substring(28);

            // Loop through rounds to generate round keys
            for (int round = 0; round < 16; round++)
            {
                // Perform shifts
                int shift = (round == 0 || round == 1 || round == 8 || round == 15) ? 1 : 2;
                leftKey = ShiftLeft(leftKey, shift);
                rightKey = ShiftLeft(rightKey, shift);

                // Combine left and right keys
                string combinedKey = leftKey + rightKey;

                // Perform second key permutation
                string roundKey = ApplyPermutation(combinedKey, matrixpc2);

                // Add the round key to the list
                roundKeys.Add(roundKey);
            }

            return roundKeys;
        }

        // Function to perform a DES round
        private string PerformDESRound(string rightHalf, string roundKey, string leftHalf)
        {
            // Expand the right half using Ebit table
            string expandedRightHalf = ApplyExpansion(rightHalf, Ebit);

            // XOR the expanded right half with the round key
            string xoredHalf = XORStrings(expandedRightHalf, roundKey);

            // Process through S-boxes and apply permutation P
            string sBoxOutput = ProcessThroughSBoxes(xoredHalf);
            string permutedOutput = ApplyPermutation(sBoxOutput, p);

            // XOR the permuted output with the left half
            string newRightHalf = XORStrings(permutedOutput, leftHalf);

            return newRightHalf;
        }

        // Helper functions

        // Function to apply a permutation using a given matrix
        private string ApplyPermutation(string input, int[,] permutationMatrix)
        {
            string output = "";
            for (int i = 0; i < permutationMatrix.GetLength(0); i++)
            {
                for (int j = 0; j < permutationMatrix.GetLength(1); j++)
                {
                    output += input[permutationMatrix[i, j] - 1];
                }
            }
            return output;
        }

        // Function to expand the input string using the Ebit table
        private string ApplyExpansion(string input, int[,] expansionTable)
        {
            string output = "";
            for (int i = 0; i < expansionTable.GetLength(0); i++)
            {
                for (int j = 0; j < expansionTable.GetLength(1); j++)
                {
                    output += input[expansionTable[i, j] - 1];
                }
            }
            return output;
        }

        // Function to process through S-boxes
        private string ProcessThroughSBoxes(string input)
        {
            string output = "";
            for (int i = 0; i < 8; i++)
            {
                // Get 6-bit chunk
                string chunk = input.Substring(i * 6, 6);
                int row = Convert.ToInt32(chunk[0].ToString() + chunk[5], 2);
                int col = Convert.ToInt32(chunk.Substring(1, 4), 2);

                // Determine which S-box to use
                int sBoxValue = GetSBoxValue(i, row, col);

                // Convert S-box output to binary and pad with zeros
                output += Convert.ToString(sBoxValue, 2).PadLeft(4, '0');
            }
            return output;
        }

        // Function to get value from a specific S-box
        private int GetSBoxValue(int sBoxIndex, int row, int col)
        {
            switch (sBoxIndex)
            {
                case 0:
                    return Sbox1[row, col];
                case 1:
                    return Sbox2[row, col];
                case 2:
                    return Sbox3[row, col];
                case 3:
                    return Sbox4[row, col];
                case 4:
                    return Sbox5[row, col];
                case 5:
                    return Sbox6[row, col];
                case 6:
                    return Sbox7[row, col];
                case 7:
                    return Sbox8[row, col];
                default:
                    throw new ArgumentOutOfRangeException(nameof(sBoxIndex), "Invalid S-box index");
            }
        }

        // Function to shift the input string left by the specified amount
        private string ShiftLeft(string input, int shift)
        {
            return input.Substring(shift) + input.Substring(0, shift);
        }

        // Function to XOR two binary strings
        private string XORStrings(string str1, string str2)
        {
            string result = "";
            for (int i = 0; i < str1.Length; i++)
            {
                result += (str1[i] ^ str2[i]).ToString();
            }
            return result;
        }

        public override string Encrypt(string plainText, string key)
        {

            //string mainPlain = "0x0123456789ABCDEF";
            //string mainCipher = "0x85E813540F0AB405";
            //string mainKey = "0x133457799BBCDFF1";

            string binaryplain = convertobinary(plainText);
            string binaryKey = convertobinary(key);

            string PC1key = PC1(binaryKey);

            List<string> SubKey32 = subKey16(PC1key);

            List<string> SubKey16 = concat16key(SubKey32);

            List<string> PC2Key = PC2(SubKey16);

            string IPPlain = IP(binaryplain);
            // string tempplain = IPPlain;

            String L0 = IPPlain.Substring(0, 32);
            String R0 = IPPlain.Substring(32);
            for (int i = 0; i < 16; i++)
            {
                List<string> bit6 = new List<string>() { };
                string L1 = R0;
                string newR0 = EBIT(R0);
                string XORresult = XOR(newR0, PC2Key[i]);
                for (int j = 0; j < XORresult.Length; j += 6)
                {
                    bit6.Add(XORresult.Substring(j, 6));
                }

                string aftersBox = SBOX(bit6);

                string F = P(aftersBox);
                string R1 = XOR(F, L0);
                L0 = L1;
                R0 = R1;


            }

            string addresult = R0 + L0;
            string finalbinaryresult = IP_1(addresult);
            string finalhexresult = "0x" + String.Format("{0:X2}", Convert.ToUInt64(finalbinaryresult, 2));

            return finalhexresult;


        }
    }
}
