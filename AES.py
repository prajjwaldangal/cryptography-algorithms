
# coding: utf-8

# In[128]:

from functools import reduce
import math

# KEY = '0f1571c947d9e8591cb7add6af7f6798' # this is what the question asks
KEY = '0f1571c947d9e8590cb7add6af7f6798'
KEY_LENGTH = len(KEY) // 2 # 16 bytes


# In[132]:


# since key length is 16 bytes, number of rounds is 14
NOR = 10
class AES:
    # Note: in this implementation, Sbox is a flat list (set) instead of a 2d array
    sBox = (
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            )
    rCon = ( 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a )

    
    def __init__(self, l, r):
        self.keyLength = l
        self.nor = r
        
    def sboxSubstitution(self, pltxt):
        """

        :param pltxt:   the plaintext of type str
        :return:        a 4x4 matrix of sbox string values
        """
        pltxt_indices = [[pltxt[i], pltxt[i+1]] for i in range(0,32,2)]
        l = len(pltxt_indices)
        opt = []
        for i in range(l):
            # since Sbox is a flat list, we will index it using just one index
            # which is row * 16 + column
            sbox_ind = int(pltxt_indices[i][0], 16) * 16 + int(pltxt_indices[i][1], 16)
            opt.append(''.join(hex(AES.sBox[sbox_ind]).split("0x")[1:]))

        mat = []
        tmp = []
        for i in range(1, 17):
            # print("type(opt[i-1]): ", type(opt[i-1]))
            tmp.append(opt[i-1])
            if i % 4 == 0:
                mat.append(tmp)
                tmp = []
        return mat
    
    def shiftRows(self, mat):
        """

        :param mat:     a 4 x 4 matrix representing bytes at each index
        :return:        a 4 x 4 matrix of strings where the 1st, 2nd, 3rd, and 4th rows are shifted by
                                    0, 1, 2, and 3 respectively
        """
        tmp = [mat[1][1], mat[1][2], mat[1][3], mat[1][0]]
        mat[1] = tmp
        tmp = [mat[2][2], mat[2][3], mat[2][0], mat[2][1]]
        mat[2] = tmp
        tmp = [mat[3][3], mat[3][0], mat[3][1], mat[3][2]]
        mat[3] = tmp
        return mat
    
    @staticmethod
    def gmul(a, b):
        """
            a:      number from the hardcoded AES mix columns matrix
            b:      number from the input matrix

            returns     the result of multiplying in GF(2^8)
        """
        p = 0
        b = int(b, 16)
        # loop run for 8 times, representing bits in a byte
        for c in range(8):
            if b & 1:
                p ^= a
            a <<= 1
            # checking if a has overflowed power of 7
            if a & 0x100:
                a ^= 0x11b
            b >>= 1
        return p
    
    @staticmethod
    def multiplyAndXor(multiplier, inp_mat):
        """
            multiplier:     is a 1 x 4 row
            inp_mat:        is the 4 X 1 column

            returns         a row after mixing (multiplying in GF(2^8) and xoring)
        """
        return AES.gmul(multiplier[0], inp_mat[0]) ^ \
                AES.gmul(multiplier[1], inp_mat[1]) ^ \
                AES.gmul(multiplier[2], inp_mat[2]) ^ \
                AES.gmul(multiplier[3], inp_mat[3]) 
    
    def mixColumns(self, inp):
        """
            inp:    is the 4x4 byte input

            returns   a 4x4 matrix of strings after mixing column
        """
        # this function makes use of helper function, multiplyAndXor
        # the code is straight forward
        comb_mat = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ]
        out = []
        i = 0
        while i < 4:
            multiplier = comb_mat[i]
            j = 0
            tmp = []
            while j < 4:
                # grabbing a column
                inp_mat = [inp[0][j], inp[1][j], inp[2][j], inp[3][j]]
                tmp.append(''.join(hex(AES.multiplyAndXor(multiplier, inp_mat)).split("0x")[1:]).zfill(2))
                j+=1
            out.append(tmp)
            i+= 1
        return out

    def addRoundKeys(self, mat, key):
        """

        :param mat:     the output after mix column or shift rows
        :param key:     the round key
        :return:        a matrix of numbers after xor-ing mat with key
        """
        i=j=0
        keyT = [[int(key[j][i], 16) for j in range(4)] for i in range(4)]
        retMat = [[0]*4 for i3 in range(4)]

        for i2 in range(4):
            for j2 in range(4):
                # print("i2: {}, j2: {}\nmat: {}\ntype(mat[i2][j2]): {}\ntype(keyT[i2][j2]): {}".format(i2,
                #                                j2, mat, type(mat[i2][j2]), type(keyT[i2][j2])))
                retMat[i2][j2] = int(mat[i2][j2], 16) ^ keyT[i2][j2]
        return retMat

    # keyExpansion algorithm is in line 188
    @staticmethod
    def rotWord(word):
        """

        :param word:    a string that whose length is 8 representing four bytes
        :return:        a rotated version of the word
        """
        return word[2:] + word[:2]

    @staticmethod
    def subWord(word):
        """

        :param word:    a string whose length is 8, representing four bytes
        :return:        a string whose length is 8, representing four bytes, after sbox substitution
        """
        r1 = word[0]
        c1 = word[1]
        r2 = word[2]
        c2 = word[3]
        r3 = word[4]
        c3 = word[5]
        r4 = word[6]
        c4 = word[7]
        sbox_ind1 = int(r1, base=16) * 16 + int(c1, base=16)
        sbox_ind2 = int(r2, base=16) * 16 + int(c2, base=16)
        sbox_ind3 = int(r3, base=16) * 16 + int(c3, base=16)
        sbox_ind4 = int(r4, base=16) * 16 + int(c4, base=16)
        byte1 = hex(AES.sBox[sbox_ind1])
        byte1 = str(byte1).split("0x")[1]
        if len(byte1) <2:
            byte1 = '0' + byte1
        byte2 = hex(AES.sBox[sbox_ind2])
        byte2 = str(byte2).split("0x")[1]
        if len(byte2) <2:
            byte2 = '0' + byte2
        byte3 = hex(AES.sBox[sbox_ind3])
        byte3 = str(byte3).split("0x")[1]
        if len(byte3) <2:
            byte3 = '0' + byte3
        byte4 = hex(AES.sBox[sbox_ind4])
        byte4 = str(byte4).split("0x")[1]
        if len(byte4) <2:
            byte4 = '0' + byte4
        return byte1+byte2+byte3+byte4

    @staticmethod
    def numToHexString(n):
        """

        :param n:   just a helper function to convert to hex as hex() return a string
        :return:    the hex part only, no 0x
        """

        if not isinstance(n, int):
            n = int(n, 16)

        h = hex(n)
        return h[2:]

    @staticmethod
    def chunkWord(strWord):
        """

        :param strWord:     a string whose length is 8
        :return:            a string whose length is 8 + three additional spaces for better illustration
        """
        return strWord[:2] + " " + strWord[2:4] + " " + strWord[4:6] + " " + strWord[6:8]

    # @property
    def keyExpansion(self):
        """
        Expands the given key of an AES algorithm and prints the process as a table.
        :return:    the keys for each round, 10 in this case
        """

        def getX(word):
            """

            :param word:    a string whose length is 8, representing 4 bytes
            :return:
            """
            return AES.rotWord(word)

        def getY(rotated):
            return AES.subWord(rotated)

        def getZ(subStr, i):
            """

            :param subStr:  the 8 characters long string obtained after sbox operation
            :param i:       the index into the rcon list, also represents the round number
            :return:        a string after xoring the first byte from subStr with rcon[round_number]
            """
            rcon = AES.rCon[i // 4]
            tmp = int(subStr[:2], 16)  ^ rcon
            tmp = AES.numToHexString(tmp)
            # convert first part of tmp to hex (R(9) = 27 = 1B)
            tmp = tmp + subStr[2:]
            s = tmp
            return s


        def printTable(ws, xs, ys, zs):
            """

            :param ws:      the list of round keys, length is 10
            :param xs:      the list of rotated words, length is 10
            :param ys:      the list of sbox substituted words after rotation, length is 10
            :param zs:      the list of y ^ r, length is 10
            :return:        -
            """

            print("w{} = {}\t\t\t\t\t| RotWord (w{}) = {} = x{}".format(0, AES.chunkWord(ws[0]),
                3,  AES.chunkWord(xs[0]), 1, end=" "))
            print("w{} = {}\t\t\t\t\t| SubWord (x{}) = {} = y{}".format(1, AES.chunkWord(ws[1]),
                1, AES.chunkWord(ys[0]), 1, end=" "))
            print("w{} = {}\t\t\t\t\t| Rcon ({}) = {} 00 00 00".format(2, AES.chunkWord(ws[2]),
                1, AES.rCon[1], end=" "))
            print("w{} = {}\t\t\t\t\t| y{} xor Rcon ({}) = {}".format(3, AES.chunkWord(ws[3]),
                1, 1, AES.chunkWord(zs[0]), end=" "))

            for i in range(4, 40):

                if i % 4 == 0:
                    print("-------------------------------------------------------------------------------")
                    wFirstInCycle = int(zs[i//4 - 1], 16) ^ int(w[i-4], 16)
                    print("w{} = w{} xor z{} = {}\t\t|".format(i, i-4, i//4,
                                                          AES.chunkWord(AES.numToHexString(wFirstInCycle))), end=" ")
                    # column 2
                    print("RotWord (w{}) = {} = x{}".format(i+3, AES.chunkWord(xs[i//4]), i//4+1))
                elif i % 4 == 1:
                    print("w{} = w{} xor w{} = {}\t\t|".format(i, i-1, i-4, AES.chunkWord(ws[i])), end=" ")
                    # column 2
                    print("SubWord (x{}) = {} = y{}".format(i//4+1, AES.chunkWord(ys[i//4]), i//4+1))
                elif i % 4 == 2:
                    print("w{} = w{} xor w{} = {}\t\t|".format(i, i-1, i-4, AES.chunkWord(ws[i])), end=" ")
                    # column 2
                    print("Rcon ({}) = {} 00 00 00".format(math.ceil(i/4), hex(AES.rCon[math.ceil(i / 4)]).split("0x")[1], end=" "))
                else:
                    print("w{} = w{} xor w{} = {}\t\t|".format(i, i-1, i-4, AES.chunkWord(ws[i])), end=" ")
                    # column 2
                    print("y{} xor Rcon ({}) = {}".format(i//4+1, i//4+1, AES.chunkWord(zs[i//4])))
            print("-------------------------------------------------------------------------------")
            print("w{} = w{} xor w{} = {}".format(40, 36, 10, AES.chunkWord(ws[40])))
            print("w{} = w{} xor w{} = {}".format(41, 40, 37, AES.chunkWord(ws[41])))
            print("w{} = w{} xor w{} = {}".format(42, 41, 38, AES.chunkWord(ws[42])))
            print("w{} = w{} xor w{} = {}".format(43, 42, 39, AES.chunkWord(ws[43])))
        w = ['' for i in range(44)]
        l = len(KEY)
        for i in range(4):
            w[i] = KEY[8*i: 8*i+8]
        
        xs = []
        ys = []
        zs = []
        # rcons = []

        for i in range(4, 44):
            # print("i: ", i)
            temp = w[i-1]
            if i % 4 == 0:
                x = getX(w[i-1])
                xs.append(x)
                y  = getY(xs[i//4-1])
                ys.append(y)
                z = getZ(y, i)
                zs.append(z)
                temp = z
            w[i] = ''.join(hex(int(w[i-4], 16) ^ int(temp, 16)).split("0x")[1:]).zfill(8)
        printTable(w, xs, ys, zs)
        return w

def format_output(msg, data, hx=False):

    print("{}\t".format(msg))
    if data:
        if isinstance(data, list):
            for i in range(4):
                print("\033[1;30;0m {}".format(data[i]))

        else:
            print("\033[1;30;0m {}".format(data))


def printTable(inp, subBytes, shifted, mc, roundKeyT):
    # <class 'list'>: [['0xab', '0x43', '0x3b', '0xe8'], ['0xae', '0xb2', '0x48', '0x53'], ['0xd0', '0xc4', '0x41', '0x1a'], ['0x1b', '0xf2', '0x4e', '0x34']]
    # let's transpose
    def transpose(mat):
        # if not mat:
        #     return []
        tmp = [["a"]*4 for i in range(4)]
        for i in range(4):
            for j in range(4):
                tmp[i][j] = subBytes[j][i]
        inp = transpose(inp)
        subBytes = transpose(subBytes)
        shifted  = transpose(shifted)
        mc = transpose(mc)

    tmp = [["a"] * 4 for i2 in range(4)]
    for i in range(4):
        for j in range(4):
            tmp[i][j] = ''.join(hex(roundKeyT[i][j]).split("0x")[1:])
    roundKeyT = tmp

    if subBytes and shifted:
        # check if need to transpose matrices
        if mc[0] == shifted[0][1:] and mc[1] == shifted[1][1:]:
            print("{}\t\t|  {}\t\t|   {}\t\t|   {}\t\t|    {}\t|".format(' '.join(inp[0]),
                                                                 ' '.join(subBytes[0]),
                                                                ' '.join(shifted[0]),
                                                                 "",
                                                                ' '.join(roundKeyT[0])))


            print("{}\t\t|  {}\t\t|   {}\t\t|   {}\t\t|    {}\t|".format(' '.join(inp[1]),
                                                                 ' '.join(subBytes[1]),
                                                                ' '.join(shifted[1]),
                                                                 "",
                                                                ' '.join(roundKeyT[1])))


            print("{}\t\t|  {}\t\t|   {}\t\t|   {}\t\t|    {}\t|".format(' '.join(inp[2]),
                                                                 ' '.join(subBytes[2]),
                                                                ' '.join(shifted[2]),
                                                                 "",
                                                                ' '.join(roundKeyT[2])))


            print("{}\t\t|  {}\t\t|   {}\t\t|   {}\t\t|    {}\t|".format(' '.join(inp[3]),
                                                                 ' '.join(subBytes[3]),
                                                                ' '.join(shifted[3]),
                                                                 " ",
                                                                ' '.join(roundKeyT[3])))
        else:
            # print("Need to transpose subBytes, shifted, mc, maybe inp")
            print("{}\t\t|  {}\t\t|   {}\t\t|   {}\t\t|    {}\t|".format(' '.join(inp[0]),
                                                                 ' '.join(subBytes[0]),
                                                                 ' '.join(shifted[0]),
                                                                 ' '.join(mc[0]),
                                                                 ' '.join(roundKeyT[0])))


            print("{}\t\t|  {}\t\t|   {}\t\t|   {}\t\t|    {}\t|".format(' '.join(inp[1]),
                                                                 ' '.join(subBytes[1]),
                                                                 ' '.join(shifted[1]),
                                                                 ' '.join(mc[1]),
                                                                 ' '.join(roundKeyT[1])))


            print("{}\t\t|  {}\t\t|   {}\t\t|   {}\t\t|    {}\t|".format(' '.join(inp[2]),
                                                                 ' '.join(subBytes[2]),
                                                                 ' '.join(shifted[2]),
                                                                 ' '.join(mc[2]),
                                                                 ' '.join(roundKeyT[2])))


            print("{}\t\t|  {}\t\t|   {}\t\t|   {}\t\t|    {}\t|".format(' '.join(inp[3]),
                                                                 ' '.join(subBytes[3]),
                                                                 ' '.join(shifted[3]),
                                                                 ' '.join(mc[3]),
                                                                 ' '.join(roundKeyT[3])))
    else:
        print("{}\t\t|\t\t\t\t\t|\t\t\t\t\t|\t\t\t\t\t|    {}\t\t|".format(' '.join(inp[0]), ' '.join(roundKeyT[0])))
        print("{}\t\t|\t\t\t\t\t|\t\t\t\t\t|\t\t\t\t\t|    {}\t\t|".format(' '.join(inp[1]), ' '.join(roundKeyT[1])))
        print("{}\t\t|\t\t\t\t\t|\t\t\t\t\t|\t\t\t\t\t|    {}\t\t|".format(' '.join(inp[2]), ' '.join(roundKeyT[2])))
        print("{}\t\t|\t\t\t\t\t|\t\t\t\t\t|\t\t\t\t\t|    {}\t\t|".format(' '.join(inp[3]), ' '.join(roundKeyT[3])))


        pass
    print("-------------------------------------------------------------------------------------------------------")
    return

if __name__ == '__main__':

    # initialize
    cipher = AES(KEY_LENGTH, NOR)
    pltxt = '0123456789abcdeffedcba9876543210'
    format_output("Plaintext: ", ' '.join(pltxt))

    # key expansion
    print("Expanding key: ", ' '.join(KEY))
    w = cipher.keyExpansion()
    inp  = pltxt
    print ("Start of Round\t|  After SubBytes\t|  After ShiftRows\t|  After MixColumns\t|  RoundKey\t\t\t|")
    for i in range(-1, cipher.nor-1):
        # format_output("Round {}".format(i), "")
        # perform sbox substitution

        # creating a matrix representation of inp_mat but we use the flattened representation in sbox func
        inpMat = [  [0]  *  4   for  i5   in   range(4)]
        for r in range(0,4):
            for c in range(0,7,2):
                # print("r: {}, c: {}".format(r, c))
                inpMat[r][c//2] = inp[r * 4 + c] + inp[r * 4 + c + 1]
        key = w[(i+1)*4:(i+2)*4]
        # let's convert the string array into array with strings
        # i.e ['0f1571c9', '47d9e859', '0cb7add6', 'af7f6798'] should be converted to
        # ==> [['0f', '15', '71', 'c9'], ['47', 'd9', ..]]
        arr = []
        # print("key: ", key)
        for i4 in range(0,4):
            tmp = []
            for j4 in range(0,7,2):
                # print("i4: {}, j4: {}, byte: {}".format(i4, j4, key[i4][j4]+key[i4][j4+1]))
                tmp.append(key[i4][j4]+key[i4][j4+1])
            arr.append(tmp)
        key = arr
        # case of when the algorithm rounds have not started
        if i < 0:
            opt_sbox = []
            shifted  = []
            mc = inpMat
        # round 0 and onwards
        else:

            # sbox takes a 32 nibble input in the form of string, set it like that so carry-over has to be accounted for
            opt_sbox = cipher.sboxSubstitution(inp)
            # shift rows
            shifted = cipher.shiftRows(opt_sbox)
            # mix columns
            if i > cipher.nor - 1:
                mc = shifted

            else:
                mc = cipher.mixColumns(shifted)
        # transposing key which is why the order is key[c2][r2], not row before column
        roundKey = [[int(key[c2][r2], 16) for c2 in range(4)] for r2 in range(4)]
        printTable(inpMat, opt_sbox, shifted, mc, roundKey)

        # add round key
        res1 = cipher.addRoundKeys(mc, key)
        # print("Length of res1: {}, of res1[0]: {}".format(len(res1), len(res1[0])))
        res = [[0, 0, 0, 0], [0,0,0,0], [0,0,0,0], [0,0,0,0]]
        for i2 in range(4):
            for j2 in range(4):
                res[i2][j2] = ''.join(hex(res1[i2][j2]).split("0x")[1:])

        inp = reduce(lambda z, y :z + y, res)
        # inp is sometimes 31 nibbles long, so have to insert a 0 to a lone character
        s = ""

        for i3 in inp:
            if len(i3) < 2:
                s += "0"+i3
            else:
                s += i3
        inp = s
        # format_output("Result after round {}".format(i), res, True)
        # format_output("", "")
        # print("##########################################################"
        #      "######################################")


