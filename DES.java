/* 
    Author: Tran Minh Duc
    Date: 19/04/2026
    Version: 1.0
    The purpose of the program is to analyse the Avalanche effect of DES and how some operations help
    make DES a good encryption algorithm.
 */

import java.util.Arrays;
import java.util.Collections;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner; 
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class DES
{
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //Initializing var as null to store input later
    static String P = "";
    static String P2 = "";
    static String K = "";
    static String K2 = "";
    static String C = "";
    static String KDecrypt = "";


    //Defining Tables

    ////FOR CIPHERTEXT
    /// 
    // Initial Permutation Table
    static int[] initialPerm = {58, 50, 42, 34, 26, 18, 10, 2,
                            60, 52, 44, 36, 28, 20, 12, 4,
                            62, 54, 46, 38, 30, 22, 14, 6,
                            64, 56, 48, 40, 32, 24, 16, 8,
                            57, 49, 41, 33, 25, 17, 9, 1,
                            59, 51, 43, 35, 27, 19, 11, 3,
                            61, 53, 45, 37, 29, 21, 13, 5,
                            63, 55, 47, 39, 31, 23, 15, 7};

    // Expansion D box Table
    static int[] expandD = {32, 1, 2, 3, 4, 5, 4, 5,
                    6, 7, 8, 9, 8, 9, 10, 11,
                    12, 13, 12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21, 20, 21,
                    22, 23, 24, 25, 24, 25, 26, 27,
                    28, 29, 28, 29, 30, 31, 32, 1};

    //Straight Permutation Table
    static int[] perTable = {16, 7, 20, 21,
                    29, 12, 28, 17,
                    1, 15, 23, 26,
                    5, 18, 31, 10,
                    2, 8, 24, 14,
                    32, 27, 3, 9,
                    19, 13, 30, 6,
                    22, 11, 4, 25};

    //S box Table as 3D arrays
    static int[][][] sBox = {{{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
		{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},

		{{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
		{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},

		{{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},

		{{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},

		{{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},

		{{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},

		{{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},

		{{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}};

    //Final Permutation Table
    static int[] finalPerm = {40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25};

    
    //Inverse E^-1 of expansion box
    static int[] inverseE = {2, 3, 4, 5, 
                        8, 9, 10, 11, 
                        14, 15, 16, 17, 
                        20, 21, 22, 23,
                        26, 27, 28, 29, 
                        32, 33, 34, 35,
                        38, 39, 40, 41, 
                        44, 45, 46, 47};

    ////FOR KEYS
    /// 
    //Permutation Choice 1  Also removes parity bits
    static int[] pc1 = {57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4};
    
    //Permutation choice 2  56 bits -> 48 bits
    static int[] pc2 = {14, 17, 11, 24, 1, 5,
			3, 28, 15, 6, 21, 10,
			23, 19, 12, 4, 26, 8,
			16, 7, 27, 20, 13, 2,
			41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48,
			44, 49, 39, 56, 34, 53,
			46, 42, 50, 36, 29, 32};

    //Bit shifts for round keys
    static int[] shiftNum = {1, 1, 2, 2,
			2, 2, 2, 2,
			1, 2, 2, 2,
			2, 2, 2, 1};


    ////FOR STORING VALUES TO COMPARE
    /// 
    //Store DES0 Bit result each round
    static String[] resultDES0 = new String[17];

    //Store DES1 Bit result each round
    static String[] resultDES1 = new String[17];

    //Store DES2 Bit result each round
    static String[] resultDES2 = new String[17];

    //Store DES3 Bit result each round
    static String[] resultDES3 = new String[17];


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Useful functions

    //Converts a String input into an int array 
    public int[] toArray(String a)
    {
        int length = a.length();

        int[] result = new int[length];
        
        for(int i = 0; i < length; i++)
        {
            result[i] = a.charAt(i) - '0';
        }

        return result;
    }

    //Converts an int[] -> String
    public String toString(int[] a)
    {
        String result = "";

        for (int i : a) 
        {
            result = result + i;
        }
        
        return result;
    }

    //XOR 2 String of numbers and return the result as a string
    public String xor(String a, String b)
    {
        String result = "";

        int[] input1 = toArray(a);
        int[] input2 = toArray(b);

        for(int i = 0; i < input1.length; i++)
        {
            if(input1[i] == input2[i])
            {
                result = result + "0";
            }

            else
            {
                result = result + "1";
            }
        }

        return result;
    }

    /*
        Rearrange the bit order
            Input: 
            String a - input string 
            int[] table - new arrangement orders
            int size - amount of desired bit output

            Output: String result
    */

    public String permute(String a, int[] table, int size)
    {
        int[] input = toArray(a);
        int[] temp = new int[size];

        for(int i = 0; i < size; i++)
        {
            temp[i] = input[table[i] - 1];
        }

        String result = toString(temp);

        return result;
    }

    
    /* 
        Compare how many bit differs from 2 binary String 
        Input: String a - String to compare
                String b - String to compare
        Output: int result
    */

    public int compare(String a, String b)
    {

        //Making sure everything is at correct bitsize
        assert a.length() == b.length() : "Input differs in length";

        int[] aft = toArray(a);
        int[] ori = toArray(b);

        int result = 0;

        for(int i = 0; i < aft.length; i++)
        {
            if(ori[i] != aft[i])
            {
                result++;
            }
        }

        return result;
    }


    /* 
    Shift bits to the left by 1
    Input: String a - string to shiftLeft
    Output: String result - Shifted string 
    */
    
    public String shiftLeft(String a)
    {
        int[] b = toArray(a);
        int[] temp = new int[b.length];

        for(int i = 1; i < b.length; i++)
        {
            temp[i-1] = b[i];
        }

        temp[b.length - 1] = b[0];

        String result = toString(temp);

        return result;
    }


    /* 
        Generate round keys
        Input: String key - main key
        Output: String[] subkey - 16 round keys in an array
    */
    public String[] genKey(String key)
    {
        //Array to store round keys
        String[] result = new String[16];

        //First key permutation
        String keyPC1 = permute(key, pc1, 56);

        //Split the key into 2 parts
        String left = keyPC1.substring(0, 28);
        String right = keyPC1.substring(28, 56);


        //Do 16 rounds
        for(int i = 0; i < 16; i++)
        {
            //Check shift amount
            if(shiftNum[i] == 1)
            {
                left = shiftLeft(left);
                right = shiftLeft(right);
            }
            
            if(shiftNum[i] == 2)
            {
                left = shiftLeft(shiftLeft(left));
                right = shiftLeft(shiftLeft(right));
            }

            //combine 2 parts then permute
            String combine = left + right;

            String roundKey = permute(combine, pc2, 48);


            //Add key to list
            result[i] = roundKey;
        }

        return result;

    }

    /* 
        SBox compression
        Input: String a - 6 bits input
                int round - Round number
        Output: String result - 4 bits output

        Var row: determined by First and Last bit
        Var col: determined by 4 middle bits
        3D array of SBox[round][row][col]
    */
        public String applySBox(String a, int round)
        {
            String row = a.substring(0, 1) + a.substring(5, 6);
            String col = a.substring(1, 5);

            //Converting string to int
            int decRow = Integer.parseInt(row, 2);
            int decCol = Integer.parseInt(col, 2);


            //Get SBox value
            int c = sBox[round][decRow][decCol];

            String result = String.format("%4s", Integer.toBinaryString(c)).replace(' ', '0');

            return result;
            
        }

    /* 
            Original DES
            Also store each round results in resultDES0[]
            Input: String pt - plaintext
                    String[] rk - array of round keys
            Output: String ct - ciphertext
    */

        public String encryptDES(String pt, String[] rk)
        {
            //Store initial value
            resultDES0[0] = pt;

            //Initial permutation
            pt = permute(pt, initialPerm, 64);

            //Split into 2 parts
            String left = pt.substring(0, 32);
            String right = pt.substring(32, 64);

            ///16 Round functions
            for(int i = 0; i < 16; i++)
            {
                //Expand right part into 48 bits
                String right48 = permute(right, expandD, 48);

                //XOR with round keys
                String rightXOR = xor(right48, rk[i]);


                int[] rightArr = toArray(rightXOR);

                String sBox = "";

                //Split into 8 parts, each with 6 bits
                for(int a = 0; a < 8; a++)
                {
                    String subString = "";
                    for(int b = 0; b < 6; b++)
                    {
                        int sub = rightArr[a * 6 + b];

                        subString = subString + Integer.toString(sub);
                    }

                    //SBox substitution, 48 bits to 32 bits 
                    String value = applySBox(subString, a);

                    //Append these together
                    sBox = sBox + value;
                }
                
                //Pbox permutation
                String rightP = permute(sBox, perTable, 32);

                //XOR with left part
                String leftXOR = xor(left, rightP);
                
                //Make the result the left part
                left = leftXOR;

                //Swap left and right
                if(i != 15)
                {
                    String temp1 = right;
                    String temp2 = left;
                    left = temp1;
                    right = temp2;
                }

                //Combine the 2 parts
                String comb = left + right;

                //Store the result of each round to comapre later
                resultDES0[i+1] = comb;

            }

            //Post round functions
            String finalComb = left + right;

            //Final permutation
            String ct = permute(finalComb, finalPerm, 64);

            return ct;
        }

        /* 
            Decrypt DES0 algorithm
            Input: String ct - Ciphertext
                    String[] rk - Round keys
            Output: String pt - PLaintext
        */

        public String decryptDES(String ct, String[] rk)
        {
            //Copying RoundKeys
            String[] rrk = rk.clone();

            //Reversing round keys
            Collections.reverse(Arrays.asList(rrk));

            String pt = encryptDES(ct, rrk);

            return pt;
        }


        /* 
            DES 1
            Encryption BUT XOR with a round key is missing from F function in all rounds. 
        */
        public String encryptDES1(String pt, String[] rk)
        {
            //Store initial value
            resultDES1[0] = pt;

            //Initial permutation
            pt = permute(pt, initialPerm, 64);

            //Split into 2 parts
            String left = pt.substring(0, 32);
            String right = pt.substring(32, 64);

            ///16 Round functions
            for(int i = 0; i < 16; i++)
            {
                //Expand right part into 48 bits
                String right48 = permute(right, expandD, 48);

                int[] rightArr = toArray(right48);

                String sBox = "";

                //Split into 8 parts, each with 6 bits
                for(int a = 0; a < 8; a++)
                {
                    String subString = "";
                    for(int b = 0; b < 6; b++)
                    {
                        int sub = rightArr[a * 6 + b];

                        subString = subString + Integer.toString(sub);
                    }

                    //SBox substitution, 48 bits to 32 bits 
                    String value = applySBox(subString, a);

                    //Append these together
                    sBox = sBox + value;
                }
                
                //Pbox permutation
                String rightP = permute(sBox, perTable, 32);

                //XOR with left part
                String leftXOR = xor(left, rightP);
                
                //Make the result the left part
                left = leftXOR;

                //Swap left and right
                if(i != 15)
                {
                    String temp1 = right;
                    String temp2 = left;
                    left = temp1;
                    right = temp2;
                }
                //Combine the 2 parts
                String comb = left + right;

                //Store the result of each round to comapre later
                resultDES1[i+1] = comb;
            }

            //Post round functions
            String finalComb = left + right;

            //Final permutation
            String ct = permute(finalComb, finalPerm, 64);

            return ct;
        }

        /* 
            Decrypt DES1 algorithm
            Input: String ct - Ciphertext
                    String[] rk - Round keys
            Output: String pt - PLaintext
        */

        public String decryptDES1(String ct, String[] rk)
        {
            //Copying RoundKeys
            String[] rrk = rk.clone();

            //Reversing round keys
            Collections.reverse(Arrays.asList(rrk));

            String pt = encryptDES1(ct, rrk);

            return pt;
        }

        /* 
            DES 2
            S-boxes are missing from F function in all rounds; instead, inverse 𝐸−1 of the Expansion
            Permutation E is used for contraction from 48 bits down to 32 bits

        */
       public String encryptDES2(String pt, String[] rk)
        {
            //Store initial value
            resultDES2[0] = pt;

            //Initial permutation
            pt = permute(pt, initialPerm, 64);

            //Split into 2 parts
            String left = pt.substring(0, 32);
            String right = pt.substring(32, 64);

            ///16 Round functions
            for(int i = 0; i < 16; i++)
            {
                //Expand right part into 48 bits
                String right48 = permute(right, expandD, 48);

                //XOR with round keys
                String rightXOR = xor(right48, rk[i]);

                //Compress to 32 bits using inverse expansion box
                String inExpand = permute(rightXOR, inverseE, 32);
                
                //Pbox permutation
                String rightP = permute(inExpand, perTable, 32);

                //XOR with left part
                String leftXOR = xor(left, rightP);
                
                //Make the result the left part
                left = leftXOR;

                //Swap left and right
                if(i != 15)
                {
                    String temp1 = right;
                    String temp2 = left;
                    left = temp1;
                    right = temp2;
                }

                //Combine the 2 parts
                String comb = left + right;

                //Store the result of each round to comapre later
                resultDES2[i+1] = comb;
            }

            //Post round functions
            String finalComb = left + right;

            //Final permutation
            String ct = permute(finalComb, finalPerm, 64);

            return ct;
        }

        /* 
            Decrypt DES2 algorithm
            Input: String ct - Ciphertext
                    String[] rk - Round keys
            Output: String pt - PLaintext
        */

        public String decryptDES2(String ct, String[] rk)
        {
            //Copying RoundKeys
            String[] rrk = rk.clone();

            //Reversing round keys
            Collections.reverse(Arrays.asList(rrk));

            String pt = encryptDES2(ct, rrk);

            return pt;
        }

        /* 
            DES 3
            Permutation P is missing from F function in all rounds
        */
       public String encryptDES3(String pt, String[] rk)
        {
            //Store initial value
            resultDES3[0] = pt;

            //Initial permutation
            pt = permute(pt, initialPerm, 64);

            //Split into 2 parts
            String left = pt.substring(0, 32);
            String right = pt.substring(32, 64);

            ///16 Round functions
            for(int i = 0; i < 16; i++)
            {
                //Expand right part into 48 bits
                String right48 = permute(right, expandD, 48);

                //XOR with round keys
                String rightXOR = xor(right48, rk[i]);


                int[] rightArr = toArray(rightXOR);

                String sBox = "";

                //Split into 8 parts, each with 6 bits
                for(int a = 0; a < 8; a++)
                {
                    String subString = "";
                    for(int b = 0; b < 6; b++)
                    {
                        int sub = rightArr[a * 6 + b];

                        subString = subString + Integer.toString(sub);
                    }

                    //SBox substitution, 48 bits to 32 bits 
                    String value = applySBox(subString, a);

                    //Append these together
                    sBox = sBox + value;
                }
                
                //XOR with left part
                String leftXOR = xor(left, sBox);
                
                //Make the result the left part
                left = leftXOR;

                //Swap left and right
                if(i != 15)
                {
                    String temp1 = right;
                    String temp2 = left;
                    left = temp1;
                    right = temp2;
                }

                ///Combine the 2 parts
                String comb = left + right;

                //Store the result of each round to comapre later
                resultDES3[i+1] = comb;
            }

            //Post round functions
            String finalComb = left + right;

            //Final permutation
            String ct = permute(finalComb, finalPerm, 64);

            return ct;
        }

        /* 
            Decrypt DES3 algorithm
            Input: String ct - Ciphertext
                    String[] rk - Round keys
            Output: String pt - PLaintext
        */

        public String decryptDES3(String ct, String[] rk)
        {
            //Copying RoundKeys
            String[] rrk = rk.clone();

            //Reversing round keys
            Collections.reverse(Arrays.asList(rrk));

            String pt = encryptDES3(ct, rrk);

            return pt;
        }

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    public static void main(String[] args) 
    {
        //Start timer to calculate total runtime
        long start = System.currentTimeMillis();


        DES test = new DES();

        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ///File reading system
        /// 
        /* 
            This is for encryption input files, the input file must only contain 4 lines
            P - Plaintext 1
            P2 - Plaintext 2
            K - Key 1
            K2 - Key 2

            File name: inputEncryption.txt
        */
        File inputEncryption = new File("inputEncryption.txt");

        //FOR DECRYPTION INPUT FILES
        File inputDecryption = new File("inputDecryption.txt");

        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //FOR ENCRYPTION
        try (Scanner readEncrypt = new Scanner(inputEncryption)) 
        {
            //Getting data from ENCRYPTION file
            P = readEncrypt.nextLine();
            P2 = readEncrypt.nextLine();
            K = readEncrypt.nextLine();
            K2 = readEncrypt.nextLine();
        } 

        catch (FileNotFoundException e) 
        {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //FOR DECRYPTION
        try (Scanner readDecrypt = new Scanner(inputDecryption)) 
        {
            //Getting data from ENCRYPTION file
            C = readDecrypt.nextLine();
            KDecrypt = readDecrypt.nextLine();
        } 

        catch (FileNotFoundException e) 
        {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }


        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        /* 
            Encrypting, storing values, comparing values
            Main processing bulk
        */

        //Generate subkeys and store
        String[] rk = test.genKey(K);
        String[] rk2 = test.genKey(K2);

        //Store bit difference for First part in each round for part 1
        int[] bitDifDES0 = new int[17];
        int[] bitDifDES1 = new int[17];
        int[] bitDifDES2 = new int[17];
        int[] bitDifDES3 = new int[17];

        //Store bit difference for First part in each round for part 2
        int[] bitDif2DES0 = new int[17];
        int[] bitDif2DES1 = new int[17];
        int[] bitDif2DES2 = new int[17];
        int[] bitDif2DES3 = new int[17];

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////// FIRST PART, COMPARING P AND P2 WITH K   NAMING CONVENTION: ct == ciphertext, D0 == DES 0, 1/2 = Plaintext 1/2
        /// ENCRYPTION DES0
        String ctD01 = test.encryptDES(P, rk);

        //COPY RESULTS FROM STORED ARRAY
        String[] tempResult = resultDES0.clone();

        String ctD02 = test.encryptDES(P2, rk);
          
        //Compare the 2 results
        for (int i = 0; i < 17; i++)
        {
            bitDifDES0[i] = test.compare(tempResult[i], resultDES0[i]);
        }

        /// ENCRYPTION DES1
        String ctD11 = test.encryptDES1(P, rk);
        String[] tempResult1 = resultDES1.clone();
        String ctD12 = test.encryptDES1(P2, rk);

        for (int i = 0; i < 17; i++)
        {
            bitDifDES1[i] = test.compare(tempResult1[i], resultDES1[i]);
        }

        /// ENCRYPTION DES2
        String ctD21 = test.encryptDES2(P, rk);
        String[] tempResult2 = resultDES2.clone();
        String ctD22 = test.encryptDES2(P2, rk);

        for (int i = 0; i < 17; i++)
        {
            bitDifDES2[i] = test.compare(tempResult2[i], resultDES2[i]);
        }

        /// ENCRYPTION DES3
        String ctD31 = test.encryptDES3(P, rk);
        String[] tempResult3 = resultDES3.clone();
        String ctD32 = test.encryptDES3(P2, rk);

        for (int i = 0; i < 17; i++)
        {
            bitDifDES3[i] = test.compare(tempResult3[i], resultDES3[i]);
        }


        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////// SECOND PART, COMPARING P UNDER K WITH P UNDER K2  NAMING CONVENTION: ct == ciphertext, D0 == DES 0, 1/2 = Plaintext 1/2, 3 == key2
        //P under K2 in DES0
        String ctD03 = test.encryptDES(P, rk2);
        for (int i = 0; i < 17; i++)
        {
            bitDif2DES0[i] = test.compare(tempResult[i], resultDES0[i]);
        }

        //P under K2 in DES1
        String ctD13 = test.encryptDES1(P, rk2);
        for (int i = 0; i < 17; i++)
        {
            bitDif2DES1[i] = test.compare(tempResult1[i], resultDES1[i]);
        }

        //P under K2 in DES2
        String ctD23 = test.encryptDES2(P, rk2);
        for (int i = 0; i < 17; i++)
        {
            bitDif2DES2[i] = test.compare(tempResult2[i], resultDES2[i]);
        }

        //P under K2 in DES3
        String ctD33 = test.encryptDES3(P, rk2);
        for (int i = 0; i < 17; i++)
        {
            bitDif2DES3[i] = test.compare(tempResult3[i], resultDES3[i]);
        }

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //Decryption logic
        String[] rk3 = test.genKey(KDecrypt);
        String decryptedC = test.decryptDES(C, rk3);
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////

        //End timer
        long end = System.currentTimeMillis();
        long timeElapsed = end - start;


        /////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ///File output system
        /// 
        /* 
            This is for encryption output files, the output will contain 4 DES algorithm results
            File name: outputEncryption.txt
        */
        try 
        {
            //FOR ENCRYPTION OUTPUT FILES
            PrintWriter writer = new PrintWriter("outputEncryption.txt");
            
            //FOR DECRYPTION OUTPUT FILES
            PrintWriter outWriter = new PrintWriter("outputDecryption.txt");

            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            /// General info
            writer.println("Avalanche Demonstration");
            writer.println("Plaintext P: " + P);
            writer.println("Plaintext P': " + P2);
            writer.println("Key: " + K);
            writer.println("Key' : " + K2);
            writer.println("Total running time: " + (timeElapsed) + " (milliseconds)");
            writer.println();


            /// PART 1 P and P2
            writer.println("P and P’ under K");
            writer.println("Ciphertext C: " + ctD01);
            writer.println("Ciphertext C': " + ctD02);
            writer.println();


            // Header
            writer.printf("%-8s %-8s %-8s %-8s %-8s%n",
                    "Round", "DES0", "DES1", "DES2", "DES3");

            //Printing each rounds
            for (int i = 0; i <= 16; i++) 
            {
                //Getting values
                int des0 = bitDifDES0[i];
                int des1 = bitDifDES1[i];
                int des2 = bitDifDES2[i];
                int des3 = bitDifDES3[i];

                writer.printf("%-8d %-8d %-8s %-8s %-8s%n",
                        i, des0, des1, des2, des3);
            }

            writer.println();


            /// PART 2 P under K AND K2
            writer.println("P under K and K'");
            writer.println("Ciphertext C: " + ctD01);
            writer.println("Ciphertext C': " + ctD03);
            writer.println();


            // Header
            writer.printf("%-8s %-8s %-8s %-8s %-8s%n",
                    "Round", "DES0", "DES1", "DES2", "DES3");

            //Printing each rounds
            for (int i = 0; i <= 16; i++) 
            {
                //Getting values
                int des0 = bitDif2DES0[i];
                int des1 = bitDif2DES1[i];
                int des2 = bitDif2DES2[i];
                int des3 = bitDif2DES3[i];

                writer.printf("%-8d %-8d %-8s %-8s %-8s%n",
                        i, des0, des1, des2, des3);
            }

            /////////////////////////////////////////////////////////////////////////////////////////////////////////////
            //Decryption
            outWriter.println("Ciphertext: " + C);
            outWriter.println("Key K: " + KDecrypt);
            outWriter.println("Plaintext: " + decryptedC);

            writer.close();
            outWriter.close();
        } 
        
        catch (FileNotFoundException e) 
        {
            e.printStackTrace();
        }
    }


    
}