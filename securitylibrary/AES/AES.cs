using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public byte[,] SBOX =
        {
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
        };
        public string[,] RijndealsGF = { { "02", "03", "01", "01" } ,
                                         { "01", "02", "03", "01" } ,
                                         { "01", "01", "02", "03" } ,
                                         { "03", "01", "01", "02" }};

        public static string[,] toMatrix(string Text, int Num_of_rows, int Num_of_columns)
        {
            string[,] Matrix = new string[Num_of_rows, Num_of_columns];
            int index = 2;
            for (int i = 0; i < Num_of_rows; i++)
            {
                for (int j = 0; j < Num_of_columns; j++)
                {
                    Matrix[j, i] = Text.Substring(index, 2);
                    index += 2;
                }
            }
            return Matrix;
        }
        public string[,] XORMatrix(string[,] PT_Matrix, string[,] K_Matrix)
        {
            string[,] Matrix = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Matrix[i, j] = XOR_(
                        comlete_8_bit(Convert.ToString(Convert.ToInt32(PT_Matrix[i, j], 16), 2)),
                        comlete_8_bit(Convert.ToString(Convert.ToInt32(K_Matrix[i, j], 16), 2))
                        );
                    Matrix[i, j] = complete_2_bit(Convert.ToString(Convert.ToInt32(Matrix[i, j], 2), 16));
                }
            }
            return Matrix;
        }
        public static string XOR_(string Text1, string Text2)
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
        public string comlete_8_bit(string Text)
        {
            int miss_len = 8 - Text.Length;
            string Matrix = "";
            for (int i = 0; i < miss_len; i++)
            {
                Matrix += '0';
            }
            Matrix += Text;
            return Matrix;
        }
        public string complete_2_bit(string Text)
        {
            int miss_len = 2 - Text.Length;
            string Matrix = "";
            for (int i = 0; i < miss_len; i++)
            {
                Matrix += '0';
            }
            Matrix += Text;
            return Matrix;
        }
        public static string[,] SubByte(string[,] PT_Matrix, byte[,] SBox)
        {
            int Num_of_rows = PT_Matrix.GetLength(0);
            int Num_of_columns = PT_Matrix.GetLength(1);
            string[,] rMatrix = new string[Num_of_rows, Num_of_columns];

            for (int i = 0; i < Num_of_rows; i++)
            {
                for (int j = 0; j < Num_of_columns; j++)
                {
                    byte inputByte = Convert.ToByte(PT_Matrix[i, j], 16);
                    int index1 = inputByte >> 4, index2 = inputByte & 0x0F;
                    byte sBoxValue = SBox[index1, index2];
                    rMatrix[i, j] = sBoxValue.ToString("X2");
                }
            }
            return rMatrix;
        }
        public string[,] ShiftRow(string[,] PT_Matrix)
        {
            string[,] temp = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    temp[i, j] = PT_Matrix[i, j];
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int sh = (i + j) % 4;
                    PT_Matrix[i, j] = temp[i, sh];
                }
            }
            return PT_Matrix;
        }

        public string[,] MixColumn(string[,] PT_Matrix)
        {
            string[,] Matrix = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        string PT = comlete_8_bit(Convert.ToString(Convert.ToInt32(PT_Matrix[k, j], 16), 2));
                        string s2 = RijndealsGF[i, k];
                        if (Matrix[i, j] == null)
                        {
                            Matrix[i, j] = Multi(PT, s2);
                        }
                        else
                        {
                            Matrix[i, j] = XOR_(Multi(PT, s2), Matrix[i, j]);
                        }
                    }
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Matrix[i, j] = complete_2_bit(Convert.ToString(Convert.ToInt32(Matrix[i, j], 2), 16));
                }
            }
            return Matrix;
        }

        public string Multi(string PT, string sh)
        {
            if (sh == "01")
            {
                return PT;
            }
            else if (sh == "02")
            {
                if (PT[0] == '0')
                {
                    return PT.Substring(1, PT.Length - 1) + "0";
                }
                else
                {
                    return XOR_(PT.Substring(1, PT.Length - 1) + "0", "00011011"); //1b
                }
            }
            else if (sh == "03")
            {
                return XOR_(Multi(PT, "02"), PT);
            }
            else if (sh == "09") //9=2*2*1
            {
                return XOR_(Multi(Multi(Multi(PT, "02"), "02"), "02"), PT);
            }
            else if (sh == "0b") //b->11=2*2+1  *2+1
            {
                return XOR_(Multi(XOR_(Multi(Multi(PT, "02"), "02"), PT), "02"), PT);
            }
            else if (sh == "0d") //d->13=3*2*2+1
            {
                return XOR_(Multi(Multi(Multi(PT, "03"), "02"), "02"), PT);
            }
            else if (sh == "0e") //e->14=3*2+1  *2
            {
                return Multi(XOR_(Multi(Multi(PT, "03"), "02"), PT), "02");
            }
            return "";
        }
        //
        public static byte[] RMatrix = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
        public byte[,] KeyGeneratee(string[,] mKey)
        {
            int N_BitKey = mKey.Length / 4;
            int N_Colomn = 4;
            int N_rounds = 10;
            byte[,] nkey = new byte[N_Colomn, N_Colomn * (N_rounds + 1)];

            for (int i = 0; i < N_BitKey; i++)
            {
                nkey[i, 0] = Convert.ToByte(mKey[i, 0], 16);
                nkey[i, 1] = Convert.ToByte(mKey[i, 1], 16);
                nkey[i, 2] = Convert.ToByte(mKey[i, 2], 16);
                nkey[i, 3] = Convert.ToByte(mKey[i, 3], 16);
            }

            for (int col = N_BitKey; col < N_Colomn * (N_rounds + 1); col++)
            {
                byte[] tmp = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    tmp[i] = nkey[i, col - 1];
                }

                if (col % N_BitKey == 0)
                {
                    byte tempByte = tmp[0];
                    tmp[0] = tmp[1];
                    tmp[1] = tmp[2];
                    tmp[2] = tmp[3];
                    tmp[3] = tempByte;

                    for (int i = 0; i < 4; i++)
                    {
                        int row = tmp[i] >> 4;
                        int colSub = tmp[i] & 0x0F;
                        tmp[i] = SBOX[row, colSub];
                    }
                    tmp[0] ^= RMatrix[col / N_BitKey];
                }

                for (int i = 0; i < 4; i++)
                {
                    nkey[i, col] = (byte)(nkey[i, col - N_BitKey] ^ tmp[i]);
                }
            }
            return nkey;
        }
        public string[,] AddRoundKey(byte[,] newkey, int round)
        {
            string[,] keystr = new string[4, 4];
            int N_BitKey = newkey.GetLength(0) / 4;
            int startingColIndex = 4 + (round * N_BitKey * 4);
            byte[,] roundKey = new byte[4, N_BitKey * 4];

            for (int row = 0; row < 4; row++)
            {
                for (int col = startingColIndex; col < startingColIndex + N_BitKey * 4; col++)
                {
                    roundKey[row, col - startingColIndex] = newkey[row, col];
                }
            }
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    keystr[row, col] = roundKey[row, col].ToString("X2");
                }
            }
            return keystr;
        }
        public string To_String(string[,] PT_Matrix)
        {
            string Matrix = "";
            for (int i = 0; i < PT_Matrix.GetLength(1); i++)
            {
                for (int j = 0; j < PT_Matrix.GetLength(0); j++)
                {
                    Matrix += PT_Matrix[j, i];
                }
            }
            return "0x" + Matrix.ToUpper();
        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string[,] plainMatrix = toMatrix(plainText, 4, 4);
            string[,] keyMatrix = toMatrix(key, 4, 4);

            byte[,] keyBox = new byte[4, 44];
            plainMatrix = XORMatrix(plainMatrix, keyMatrix);
            keyBox = KeyGeneratee(keyMatrix);
            for (int i = 0; i <= 8; i++)
            {
                plainMatrix = SubByte(plainMatrix, SBOX);
                plainMatrix = ShiftRow(plainMatrix);
                plainMatrix = MixColumn(plainMatrix);
                keyMatrix = AddRoundKey(keyBox, i);
                plainMatrix = XORMatrix(plainMatrix, keyMatrix);
            }

            plainMatrix = SubByte(plainMatrix, SBOX);
            plainMatrix = ShiftRow(plainMatrix);
            keyMatrix = AddRoundKey(keyBox, 9);
            plainMatrix = XORMatrix(plainMatrix, keyMatrix);
            return To_String(plainMatrix);
        }
        public override string Decrypt(string cipherText, string key)
        {
            string[,] C_T = new string[4, 4];
            string[,] k = new string[4, 4];
            int index = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    C_T[j, i] = (cipherText[index].ToString() + cipherText[index + 1].ToString());
                    k[j, i] = (key[index].ToString() + key[index + 1].ToString());
                    index += 2;
                }
            }
            for (int i = 0; i < 10; i++)
            {
                keys.Add(new string[4, 4]);
            }
            keys[0] = get_key_Round(k, 0);

            for (int i = 1; i <= 9; i++)
            {

                keys[i] = get_key_Round(keys[i - 1], i);
            }

            //Round 0
            C_T = xor_2mat(C_T, keys[9]);
            C_T = Sub_Bytes_Dec(Shift_Rows_Dec(C_T));


            //Round for 9 times
            string[,] str = new string[4, 4];
            for (int i = 1; i <= 9; i++)
            {
                str = xor_2mat(keys[9 - i], C_T);
                str = Mix_Columns_Dec(str);

                str = Shift_Rows_Dec(str);
                str = Sub_Bytes_Dec(str);
                for (int m = 0; m < 4; m++)
                {
                    for (int q = 0; q < 4; q++)
                        C_T[m, q] = str[m, q];
                }
            }

            //last Round
            C_T = xor_2mat(k, C_T);

            string fin = "";

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    fin += C_T[j, i];
                }
            }
            return "0x" + fin;
        }


        /****************************************************************************/
        // helper function for Decryption :
        List<string[,]> keys = new List<string[,]>();
        public string[,] get_key_Round(string[,] last, int num)
        {
            string[] first_column = new string[4];
            string[] C1 = new string[4];

            //Get first_column and last_column
            for (int i = 0; i < 4; i++)
            {
                first_column[i] = last[i, 3];
                C1[i] = last[i, 0];
            }

            //rotate it
            string tmp = first_column[0];
            for (int i = 1; i < 4; i++)
                first_column[i - 1] = first_column[i];
            first_column[3] = tmp;

            //substdude 
            string[,] SBOX = {
            {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
            {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
            {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
            {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
            {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},
            {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},
            {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},
            {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},
            {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},
            {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},
            {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},
            {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},
            {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
            {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},
            {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},
            {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"}
        };
            for (int i = 0; i < 4; i++)
            {
                int r = int.Parse(first_column[i][0].ToString(), System.Globalization.NumberStyles.HexNumber);
                int c = int.Parse(first_column[i][1].ToString(), System.Globalization.NumberStyles.HexNumber);
                first_column[i] = SBOX[r, c];
            }

            //xor
            int Rcon = num;

            string[,] Con =
            {
                { "01", "02","04","08","10","20","40","80","1b","36"},
                { "00", "00","00","00","00","00","00","00","00","00"},
                { "00", "00","00","00","00","00","00","00","00","00"},
                { "00", "00","00","00","00","00","00","00","00","00"}
            };

            string[] C2 = new string[4];
            for (int i = 0; i < 4; i++)
                C2[i] = Con[i, Rcon];

            for (int i = 0; i < 4; i++)
                C1[i] = get_hexa(x_or(get_binary_str(C1[i]), get_binary_str(C2[i])));

            string[,] ans = new string[4, 4];

            //fill first column
            for (int i = 0; i < 4; i++)
                ans[i, 0] = get_hexa(x_or(get_binary_str(C1[i]), get_binary_str(first_column[i])));

            //fill all columns
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    ans[j, i] = get_hexa(x_or(get_binary_str(last[j, i]), get_binary_str(ans[j, i - 1])));
                }
            }
            return ans;
        }
        public string[,] Shift_Rows_Dec(string[,] plain_text)
        {
            for (int i = 0; i < 4; i++)
            {
                List<string> end = new List<string>(i);
                List<string> start = new List<string>(4 - i);
                int count = i;
                for (int j = 3; count > 0; j--)
                {
                    end.Add(plain_text[i, j]);
                    count--;
                }
                end.Reverse();
                for (int j = 0; j < 4 - i; j++)
                    start.Add(plain_text[i, j]);

                int st = 0;
                for (int j = 0; j < end.Count; j++)
                    plain_text[i, st++] = end[j];

                for (int j = 0; j < start.Count; j++)
                    plain_text[i, st++] = start[j];
            }
            return plain_text;
        }
        public string[,] Sub_Bytes_Dec(string[,] cipher_text)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string temp = cipher_text[i, j];
                    cipher_text[i, j] = get_R_C(temp);
                }
            }
            return cipher_text;
        }
        public int shift_left(int y)
        {
            y *= 2;
            if (y > 255)
                y ^= 27;
            //101010001010
            string binary = Convert.ToString(y, 2);
            string t = "";
            for (int i = 0; i < 8 - binary.Length; i++)
            {
                t += "0";
            }
            binary = t + binary;
            binary = binary.Substring(binary.Length - 8, 8);
            y = Convert.ToInt32(binary, 2);
            return y;
        }
        public int mul_Dec(string str1, string str2)
        {
            str1 = str1.ToUpper();
            str2 = str2.ToUpper();

            Dictionary<char, string> data = new Dictionary<char, string>();

            data.Add('0', "0000");
            data.Add('1', "0001");
            data.Add('2', "0010");
            data.Add('3', "0011");
            data.Add('4', "0100");
            data.Add('5', "0101");
            data.Add('6', "0110");
            data.Add('7', "0111");
            data.Add('8', "1000");
            data.Add('9', "1001");
            data.Add('A', "1010");
            data.Add('B', "1011");
            data.Add('C', "1100");
            data.Add('D', "1101");
            data.Add('E', "1110");
            data.Add('F', "1111");


            string res1 = "", res2 = "";
            for (int i = 0; i < str1.Length; i++)
            {
                res1 += data[str1[i]];
                res2 += data[str2[i]];
            }
            int temp1 = Convert.ToInt32(res1, 2);
            int temp2 = Convert.ToInt32(res2, 2);

            if (temp1 == 9)
            {
                int x = shift_left(temp2);
                x = shift_left(x);
                x = shift_left(x);
                x ^= temp2;
                return x;
            }
            else if (temp1 == 11)
            {
                int x = shift_left(temp2);
                x = shift_left(x);
                x ^= temp2;
                x = shift_left(x);
                x ^= temp2;
                return x;
            }
            else if (temp1 == 13)
            {
                int x = shift_left(temp2);
                x ^= temp2;
                x = shift_left(x);
                x = shift_left(x);
                x ^= temp2;
                return x;
            }
            else if (temp1 == 14)
            {
                int x = shift_left(temp2);
                x ^= temp2;
                x = shift_left(x);
                x ^= temp2;
                x = shift_left(x);
                return x;
            }
            return 0;
        }
        public string[,] Mix_Columns_Dec(string[,] plain_Text)
        {

            string[,] temp = {
                {"0E","0B","0D","09"},
                {"09","0E","0B","0D"},
                { "0D","09","0E","0B"},
                { "0B","0D","09","0E"}
            };
            string[,] result = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int[] array = new int[4];
                    for (int k = 0; k < 4; k++)
                    {
                        array[k] = mul_Dec(temp[i, k], plain_Text[k, j]);
                    }
                    int x = (array[0] ^ array[1] ^ array[2] ^ array[3]);
                    result[i, j] = x.ToString("X2");
                }
            }
            return result;
        }
        string[,] xor_2mat(string[,] a, string[,] b)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    a[i, j] = get_hexa(x_or(get_binary_str(a[i, j]), get_binary_str(b[i, j])));
                }
            }
            return a;
        }
        public string get_hexa(string s)
        {
            Dictionary<string, string> dict = new Dictionary<string, string>();
            dict.Add("0000", "0");
            dict.Add("0001", "1");
            dict.Add("0010", "2");
            dict.Add("0011", "3");
            dict.Add("0100", "4");
            dict.Add("0101", "5");
            dict.Add("0110", "6");
            dict.Add("0111", "7");
            dict.Add("1000", "8");
            dict.Add("1001", "9");
            dict.Add("1010", "A");
            dict.Add("1011", "B");
            dict.Add("1100", "C");
            dict.Add("1101", "D");
            dict.Add("1110", "E");
            dict.Add("1111", "F");
            string tmp1 = s.Substring(0, 4);
            string tmp2 = s.Substring(4, 4);
            return (dict[tmp1] + dict[tmp2]);
        }
        public string x_or(string x, string y)
        {
            string res = "";
            for (int i = 0; i < x.Length; i++)
            {
                if (x[i] == y[i])
                    res += '0';
                else
                    res += '1';
            }
            return res;
        }
        public string get_binary_str(string hexa)
        {
            hexa = hexa.ToUpper();
            Dictionary<char, string> data = new Dictionary<char, string>();

            data.Add('0', "0000");
            data.Add('1', "0001");
            data.Add('2', "0010");
            data.Add('3', "0011");
            data.Add('4', "0100");
            data.Add('5', "0101");
            data.Add('6', "0110");
            data.Add('7', "0111");
            data.Add('8', "1000");
            data.Add('9', "1001");
            data.Add('A', "1010");
            data.Add('B', "1011");
            data.Add('C', "1100");
            data.Add('D', "1101");
            data.Add('E', "1110");
            data.Add('F', "1111");

            string ans = data[hexa[0]] + data[hexa[1]];

            return ans;

        }
        public string get_R_C(string temp)
        {
            string[,] S_BOX =
               {
            {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
            {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
            {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
            {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
            {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},
            {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},
            {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},
            {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},
            {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},
            {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},
            {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},
            {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},
            {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
            {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},
            {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},
            {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"}
        };
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    if (S_BOX[i, j] == temp)
                    {
                        string hex1 = i.ToString("X1");
                        string hex2 = j.ToString("X1");
                        return hex1 + hex2;
                    }
                }
            }
            return "";
        }

    }
}