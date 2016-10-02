import rijndael_sbox
from random import randint


class Rijndael(object):
    def __init__(self, statesize, keysize):
        # State and cipher key block dimensions.
        if statesize % 64 != 0 or statesize < 128 or statesize > 256:
            raise ValueError("The given state size is invalid.")
        if keysize % 64 != 0 or keysize < 128 or keysize > 256:
            raise ValueError("The given key size is invalid.")

        self._block_rows = 4
        self._state_cols = int(statesize / 8 / self._block_rows)
        self._state_size = self._state_cols * self._block_rows
        self._key_cols = int(keysize / 8 / self._block_rows)
        self._key_size = self._key_cols * self._block_rows

        self._maxrounds = 10
        if keysize >= 256 or statesize >= 256:
            self._maxrounds = 14
        elif keysize >= 192 or statesize >= 192:
            self._maxrounds = 12
        self._round = 0
        self._sbox = rijndael_sbox.init_sbox()
        self._blocks = []
        self._enckey = bytearray()
        self._expkey = bytearray()

    def __repr__(self):
        return "Rijndael(statesize={} bits ({}x{}={} bytes); keysize={} bits ({}x{}={} bytes); blocks={}; round={} of {})".format(
            self._state_size * 8,
            self._block_rows,
            self._state_cols,
            self._state_size,
            self._key_size * 8,
            self._block_rows,
            self._key_cols,
            self._key_size,
            len(self._blocks),
            self._round,
            self._maxrounds
        )

    @staticmethod
    def _initialiseinputbytes(inputstring, blocksize, padmethod):
        if len(inputstring) < 1:
            return bytearray(blocksize)
        outputbytes = bytearray()
        outputbytes.extend(map(ord, inputstring))
        if padmethod == 0:
            outputbytes = Rijndael._pad_zeroes(outputbytes, blocksize)
        elif padmethod == 1:
            outputbytes = Rijndael._pad_x923(outputbytes, blocksize)
        elif padmethod == 2:
            outputbytes = Rijndael._pad_iso10126(outputbytes, blocksize)
        elif padmethod == 3:
            outputbytes = Rijndael._pad_pkcs7(outputbytes, blocksize)
        return outputbytes

    @staticmethod
    def _pad_zeroes(inputbytes, blocksize):
        padlen = blocksize - (len(inputbytes) % blocksize)
        if padlen == 0:
            return inputbytes

        inputbytes = inputbytes.ljust(len(inputbytes)+padlen, b'\x00')
        return inputbytes

    @staticmethod
    def _pad_x923(inputbytes, blocksize):
        padlen = blocksize - (len(inputbytes) % blocksize)
        if padlen == 0:
            padlen = blocksize

        inputbytes = inputbytes.ljust(len(inputbytes)+padlen-1, b'\x00')
        inputbytes.append(padlen)
        return inputbytes

    @staticmethod
    def _pad_iso10126(inputbytes, blocksize):
        padlen = blocksize - (len(inputbytes) % blocksize)
        if padlen == 0:
            padlen = blocksize

        for _ in range(padlen-1):
            inputbytes.append(randint(0, 255))
        inputbytes.append(padlen)
        return inputbytes

    @staticmethod
    def _pad_pkcs7(inputbytes, blocksize):
        padlen = blocksize - (len(inputbytes) % blocksize)
        if padlen == 0:
            padlen = blocksize

        for _ in range(padlen):
            inputbytes.append(padlen)
        return inputbytes

    def _transformbytestoblocks(self, inputbytes):
        for x in range(0, len(inputbytes), self._state_size):
            block = Block(self._state_cols, self._block_rows)
            block.setblockdata(inputbytes[x:x+self._state_size])
            self._blocks.append(block)

    def createdatablocks(self, cryptdata):
        bytedata = Rijndael._initialiseinputbytes(cryptdata, self._state_size, 3)
        self._transformbytestoblocks(bytedata)

    def setencryptionkey(self, enckey):
        self._enckey = Rijndael._initialiseinputbytes(enckey, self._key_size, 0)
        self._keyschedule()

    def subbytes(self):
        for block in self._blocks:
            for col in range(block.getcolcount()):
                for row in range(block.getrowcount()):
                    block.setcell(row, col, self._sbox[block.getcell(row, col)])

    def shiftrows(self):
        for block in self._blocks:
            for i in range(self._block_rows):
                block.rotaterowleft(i, i)

    @staticmethod
    def _galoismultiply(a, b):
        p = 0
        for counter in range(8):
            if b & 0x01 != 0:
                p ^= a
            hi_bit_set = a & 0x80
            a = rijndael_sbox.lsh(a, 1, 8)
            if hi_bit_set != 0:
                a ^= 0x1B
            b >>= 1
        return p

    def mixcolumns(self):
        for block in range(len(self._blocks)):
            for col in range(self._blocks[block].getcolcount()):
                orig = self._blocks[block].getcolumn(col)
                self._blocks[block].setcell(0, col, Rijndael._galoismultiply(0x02, orig[0]) ^ Rijndael._galoismultiply(0x03, orig[1]) ^ orig[2] ^ orig[3])
                self._blocks[block].setcell(1, col, orig[0] ^ Rijndael._galoismultiply(0x02, orig[1]) ^ Rijndael._galoismultiply(0x03, orig[2]) ^ orig[3])
                self._blocks[block].setcell(2, col, orig[0] ^ orig[1] ^ Rijndael._galoismultiply(0x02, orig[2]) ^ Rijndael._galoismultiply(0x03, orig[3]))
                self._blocks[block].setcell(3, col, Rijndael._galoismultiply(0x03, orig[0]) ^ orig[1] ^ orig[2] ^ Rijndael._galoismultiply(0x02, orig[3]))

    @staticmethod
    def _rcon(idx):
        if idx <= 0:
            return 0
        c = 1
        while idx > 1:
            c = Rijndael._galoismultiply(0x02, c)
            idx -= 1
        return c

    @staticmethod
    def _rotateword(word):
        return word[1:] + word[:1]

    def _subword(self, word):
        for i in range(4):
            word[i] = self._sbox[word[i]]
        return word

    @staticmethod
    def _xorword(word1, word2):
        for i in range(4):
            word1[i] ^= word2[i]
        return word1

    @staticmethod
    def _keyexpansion(a):
        pass

    def _keyschedule(self):
        n = self._key_cols                            # 32-bit words in original key.
        b = (self._maxrounds + 1) * self._state_cols  # 32-bit words in generated key schedule.
        self._expkey = bytearray(b*4)
        self._expkey[:n*4] = self._enckey[:n*4]

        for i in range(n, b):
            prev_word = self._expkey[(i-1)*4:i*4]
            keyback_word = self._expkey[(i-n)*4:(i-n+1)*4]

            t = prev_word
            if i % n == 0:
                t = Rijndael._rotateword(prev_word)
                t = self._subword(t)
                t[0] ^= Rijndael._rcon(int(i/n))
            elif n > 6 and i % n == 4:
                t = self._subword(t)
            exp_word = Rijndael._xorword(keyback_word, t)

            self._expkey[i*4:(i+1)*4] = exp_word

    def addroundkey(self):
        if self._round >= self._maxrounds:
            raise Exception("No more rounds left to run.")
        w = self._state_cols*self._round
        roundkey = self._expkey[w*4:(w+self._state_cols)*4]
        for block in self._blocks:
            for col in range(block.getcolcount()):
                for row in range(block.getrowcount()):
                    block.setcell(row, col, block.getcell(row, col) ^ roundkey[row+col*block.getrowcount()])
        self._round += 1

    def encrypt(self):
        while self._round < self._maxrounds:
            self.subbytes()
            self.shiftrows()
            if self._round < self._maxrounds - 1:
                self.mixcolumns()
            self.addroundkey()

    def decrypt(self):
        pass

    def getcipher(self):
        cipher = bytearray()
        for block in self._blocks:
            cipher += block.getblockdata()
        return cipher


class Block(object):
    def __init__(self, ncol, nrow):
        if ncol < 1 or nrow < 1:
            raise ValueError("Block dimensions are invalid.")

        self._columns = ncol
        self._rows = nrow
        self._blocksize = self._columns*self._rows
        self._blockdata = bytearray(self._blocksize)

    def __iter__(self):
        for b in self._blockdata:
            yield b

    def __len__(self):
        return len(self._blockdata)

    def __repr__(self):
        return "Block(rows={}; cols={}; blocksize={} bits)".format(
            self._rows,
            self._columns,
            self._blocksize*8
        )

    def __str__(self):
        txt = ""
        for row in range(self._rows):
            for col in range(self._columns):
                txt += "{:#04x} ".format(self.getcell(row, col))
            txt += '\n'
        return txt

    def getblockdata(self):
        return self._blockdata

    def setblockdata(self, inputbytes):
        if len(inputbytes) != self._blocksize:
            raise ValueError("Provided data does not match block size. ({} != {})".format(len(inputbytes), self._blocksize))
        self._blockdata = inputbytes

    def getcolcount(self):
        return self._columns

    def getrowcount(self):
        return self._rows

    def getcell(self, row, col):
        if 0 >= row > self._rows or 0 >= col > self._columns:
            raise ValueError("Cell location is out of range.")
        return self._blockdata[row+col*self._rows]

    def setcell(self, row, col, value):
        if 0 >= row > self._rows or 0 >= col > self._columns:
            raise ValueError("Cell location is out of range.")
        self._blockdata[row+col*self._rows] = value

    def getrow(self, row):
        if 0 >= row > self._rows:
            raise ValueError("Row index is out of range.")
        return self._blockdata[row:self._blocksize-self._rows+1+row:self._rows]

    def getrows(self):
        for i in range(self._rows):
            yield self.getrow(i)

    def setrow(self, row, values):
        if 0 >= row > self._rows:
            raise ValueError("Row index is out of range.")
        if len(values) != self._columns:
            raise ValueError("Length of data does not match block columns count.")
        self._blockdata[row:self._blocksize - self._rows + 1 + row:self._rows] = values

    def rotaterowleft(self, row, steps):
        if 0 >= row > self._rows:
            raise ValueError("Row index is out of range.")
        steps %= self._columns

        rowdata = self.getrow(row)
        rowdata = rowdata[steps:] + rowdata[:steps]
        self.setrow(row, rowdata)

    def getcolumn(self, col):
        if 0 >= col > self._columns:
            raise ValueError("Column index is out of range.")
        return self._blockdata[self._rows*col:self._rows*(col+1)]

    def getcolumns(self):
        for i in range(self._columns):
            yield self.getcolumn(i)


def main():
    block = Block(4, 4)
    testdata = bytearray()
    testdata.extend(map(ord, "abcdefghijklmnop"))
    block.setblockdata(testdata)

    assert block.getcolumn(0) == b"abcd"
    assert block.getrow(0) == b"aeim"
    block.rotaterowleft(0, 1)
    assert block.getrow(0) == b"eima"
    block.setrow(0, bytearray("abcd", encoding="UTF-8"))
    assert block.getrow(0) == b"abcd"
    block.setcell(0, 0, ord('x'))
    assert block.getcell(0, 0) == ord('x')
    print("Rijndael (Block): All tests passed.")

    cryptoprovider = Rijndael(256, 128)
    cryptoprovider.setencryptionkey("")
    plaintext = "Hello, world! This."
    print("\nPlaintext:", plaintext)
    cryptoprovider.createdatablocks(plaintext)
    printcryptoblocks(cryptoprovider)
    cryptoprovider.subbytes()
    print("SubBytes step:")
    printcryptoblocks(cryptoprovider)
    cryptoprovider.shiftrows()
    print("ShiftRows step:")
    printcryptoblocks(cryptoprovider)
    cryptoprovider.mixcolumns()
    print("MixColumns step:")
    assert Rijndael._galoismultiply(0x53, 0xCA) == 0x01
    printcryptoblocks(cryptoprovider)
    print("AddRoundKey step:")
    assert Rijndael._rcon(4) == 0x08
    assert Rijndael._rcon(255) == 0x8D
    cryptoprovider._enckey = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
    cryptoprovider._keyschedule()

    print("Key:")
    for i in range(len(cryptoprovider._enckey)):
        print("{:#04x} ".format(cryptoprovider._enckey[i]), end="")
    print("\nExtended key:")
    for i in range(int(len(cryptoprovider._expkey)/16)):
        txt = ""
        for j in range(16):
            txt += "{:#04x} ".format(cryptoprovider._expkey[i*16+j])
        print(txt)

    for i in range(cryptoprovider._maxrounds):
        cryptoprovider.addroundkey()
    printcryptoblocks(cryptoprovider)

    print("Rijndael (Rijndael): All tests passed.")


def printcryptoblocks(cp):
    print("\nCurrent state of the datablocks:")
    print(repr(cp))
    for block in cp._blocks:
        print(repr(block))
        print(block)


if __name__ == '__main__':
    main()
