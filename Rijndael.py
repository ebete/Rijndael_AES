import rijndael_sbox
from random import randint


class Rijndael(object):
    def __init__(self, statesize=128, keysize=128):
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

        self._lastround = 9
        if keysize >= 256 or statesize >= 256:
            self._lastround = 13
        elif keysize >= 192 or statesize >= 192:
            self._lastround = 11
        self._round = 0
        self._sbox = rijndael_sbox.init_sbox()
        self._sbox_inv = rijndael_sbox.init_sbox_inverse()
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
            self._round+1,
            self._lastround+1
        )

    @staticmethod
    def _pad_zeroes(inputbytes, blocksize):
        padlen = blocksize - (len(inputbytes) % blocksize)
        if padlen == blocksize and len(inputbytes) > 0:
            return inputbytes

        inputbytes = inputbytes.ljust(len(inputbytes)+padlen, b'\x00')
        return inputbytes

    @staticmethod
    def _pad_x923(inputbytes, blocksize):
        padlen = blocksize - (len(inputbytes) % blocksize)

        inputbytes = inputbytes.ljust(len(inputbytes)+padlen-1, b'\x00')
        inputbytes.append(padlen)
        return inputbytes

    @staticmethod
    def _pad_iso10126(inputbytes, blocksize):
        padlen = blocksize - (len(inputbytes) % blocksize)

        for _ in range(padlen-1):
            inputbytes.append(randint(0, 255))
        inputbytes.append(padlen)
        return inputbytes

    @staticmethod
    def _pad_pkcs7(inputbytes, blocksize):
        padlen = blocksize - (len(inputbytes) % blocksize)

        for _ in range(padlen):
            inputbytes.append(padlen)
        return inputbytes

    @staticmethod
    def _initialiseinputbytes(inputbytes, blocksize, padmethod=3):
        if padmethod == 0:
            outputbytes = Rijndael._pad_zeroes(inputbytes, blocksize)
        elif padmethod == 1:
            outputbytes = Rijndael._pad_x923(inputbytes, blocksize)
        elif padmethod == 2:
            outputbytes = Rijndael._pad_iso10126(inputbytes, blocksize)
        else:
            outputbytes = Rijndael._pad_pkcs7(inputbytes, blocksize)
        return outputbytes

    def _transformbytestoblocks(self, inputbytes):
        for x in range(0, len(inputbytes), self._state_size):
            block = Block(self._state_cols, self._block_rows)
            block.setblockdata(inputbytes[x:x+self._state_size])
            self._blocks.append(block)

    @staticmethod
    def _stringtobytes(inputstring):
        outputbytes = bytearray()
        outputbytes.extend(map(ord, inputstring))
        return outputbytes

    def createdatablocks(self, cryptdata):
        if type(cryptdata) is not bytearray:
            cryptdata = Rijndael._stringtobytes(cryptdata)
        cryptdata = Rijndael._initialiseinputbytes(cryptdata, self._state_size, 0)
        self._transformbytestoblocks(cryptdata)

    def setencryptionkey(self, enckey):
        if type(enckey) is not bytearray:
            enckey = Rijndael._stringtobytes(enckey)
        self._enckey = Rijndael._initialiseinputbytes(enckey, self._key_size, 0)
        self._keyschedule()

    def _subbytes(self):
        for block in self._blocks:
            for col in range(block.getcolcount()):
                for row in range(block.getrowcount()):
                    subcell = self._sbox[block.getcell(row, col)]
                    block.setcell(row, col, subcell)

    def _subbytes_inv(self):
        for block in self._blocks:
            for col in range(block.getcolcount()):
                for row in range(block.getrowcount()):
                    subcell = self._sbox_inv[block.getcell(row, col)]
                    block.setcell(row, col, subcell)

    def _shiftrows(self):
        for block in self._blocks:
            for i in range(self._block_rows):
                block.rotaterowleft(i, i)

    def _shiftrows_inv(self):
        for block in self._blocks:
            for i in range(self._block_rows):
                block.rotaterowleft(i, self._block_rows-i)

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

    def _mixcolumns(self):
        for block in range(len(self._blocks)):
            for col in range(self._blocks[block].getcolcount()):
                orig = self._blocks[block].getcolumn(col)
                self._blocks[block].setcell(0, col,
                                            Rijndael._galoismultiply(0x02, orig[0]) ^
                                            Rijndael._galoismultiply(0x03, orig[1]) ^
                                            orig[2] ^
                                            orig[3])
                self._blocks[block].setcell(1, col,
                                            orig[0] ^
                                            Rijndael._galoismultiply(0x02, orig[1]) ^
                                            Rijndael._galoismultiply(0x03, orig[2]) ^
                                            orig[3])
                self._blocks[block].setcell(2, col,
                                            orig[0] ^
                                            orig[1] ^
                                            Rijndael._galoismultiply(0x02, orig[2]) ^
                                            Rijndael._galoismultiply(0x03, orig[3]))
                self._blocks[block].setcell(3, col,
                                            Rijndael._galoismultiply(0x03, orig[0]) ^
                                            orig[1] ^
                                            orig[2] ^
                                            Rijndael._galoismultiply(0x02, orig[3]))

    def _mixcolumns_inv(self):
        for block in range(len(self._blocks)):
            for col in range(self._blocks[block].getcolcount()):
                orig = self._blocks[block].getcolumn(col)
                self._blocks[block].setcell(0, col,
                                            Rijndael._galoismultiply(0x0e, orig[0]) ^
                                            Rijndael._galoismultiply(0x0b, orig[1]) ^
                                            Rijndael._galoismultiply(0x0d, orig[2]) ^
                                            Rijndael._galoismultiply(0x09, orig[3]))
                self._blocks[block].setcell(1, col,
                                            Rijndael._galoismultiply(0x09, orig[0]) ^
                                            Rijndael._galoismultiply(0x0e, orig[1]) ^
                                            Rijndael._galoismultiply(0x0b, orig[2]) ^
                                            Rijndael._galoismultiply(0x0d, orig[3]))
                self._blocks[block].setcell(2, col,
                                            Rijndael._galoismultiply(0x0d, orig[0]) ^
                                            Rijndael._galoismultiply(0x09, orig[1]) ^
                                            Rijndael._galoismultiply(0x0e, orig[2]) ^
                                            Rijndael._galoismultiply(0x0b, orig[3]))
                self._blocks[block].setcell(3, col,
                                            Rijndael._galoismultiply(0x0b, orig[0]) ^
                                            Rijndael._galoismultiply(0x0d, orig[1]) ^
                                            Rijndael._galoismultiply(0x09, orig[2]) ^
                                            Rijndael._galoismultiply(0x0e, orig[3]))

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

    def _keyschedule(self):
        n = self._key_cols                            # 32-bit words in original key.
        b = (self._lastround + 2) * self._state_cols  # 32-bit words in generated key schedule.
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

    def _addroundkey(self, keyround):
        if keyround > self._lastround:
            raise Exception("No more rounds left to run.")
        w = self._state_cols*keyround
        roundkey = self._expkey[w*4:(w+self._state_cols)*4]
        for block in self._blocks:
            for col in range(block.getcolcount()):
                for row in range(block.getrowcount()):
                    enccell = block.getcell(row, col) ^ roundkey[row + col * block.getrowcount()]
                    block.setcell(row, col, enccell)

    def encrypt(self):
        self._round = 0
        while self._round <= self._lastround:
            self._subbytes()
            self._shiftrows()
            if self._round < self._lastround:
                self._mixcolumns()
            self._addroundkey(self._round)
            self._round += 1
        self._round -= 1

    def decrypt(self):
        self._round = self._lastround
        while self._round >= 0:
            self._addroundkey(self._round)
            if self._round < self._lastround:
                self._mixcolumns_inv()
            self._shiftrows_inv()
            self._subbytes_inv()
            self._round -= 1
        self._round += 1

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

    assert Rijndael._rcon(4) == 0x08
    assert Rijndael._rcon(255) == 0x8D
    assert Rijndael._galoismultiply(0x53, 0xCA) == 0x01

    ba = bytearray(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F")
    cryptoprovider = Rijndael(128, 128)
    cryptoprovider.setencryptionkey(ba)
    cryptoprovider.createdatablocks(ba)

    assert cryptoprovider.getcipher() == ba

    print("\nInitialisation state (blocks/padding/keystate):")
    print("Data:")
    printcryptoblocks(cryptoprovider)
    print("Key:")
    for i in range(len(cryptoprovider._enckey)):
        print("{:#04x} ".format(cryptoprovider._enckey[i]), end="")
    print("\nExtended key:")
    for i in range(int(len(cryptoprovider._expkey)/16)):
        txt = ""
        for j in range(16):
            txt += "{:#04x} ".format(cryptoprovider._expkey[i*16+j])
        print(txt)
    print()

    print("SubBytes step:")
    assertdata = cryptoprovider._blocks[0]._blockdata
    cryptoprovider._subbytes()
    printcryptoblocks(cryptoprovider)
    print("SubBytes_inv step:")
    cryptoprovider._subbytes_inv()
    printcryptoblocks(cryptoprovider)
    assert cryptoprovider._blocks[0]._blockdata == assertdata

    print("ShiftRows step:")
    assertdata = cryptoprovider._blocks[0]._blockdata
    cryptoprovider._shiftrows()
    printcryptoblocks(cryptoprovider)
    print("ShiftRows_inv step:")
    cryptoprovider._shiftrows_inv()
    printcryptoblocks(cryptoprovider)
    assert cryptoprovider._blocks[0]._blockdata == assertdata

    print("MixColumns step:")
    assertdata = cryptoprovider._blocks[0]._blockdata
    cryptoprovider._mixcolumns()
    printcryptoblocks(cryptoprovider)
    print("MixColumns_inv step:")
    cryptoprovider._mixcolumns_inv()
    printcryptoblocks(cryptoprovider)
    assert cryptoprovider._blocks[0]._blockdata == assertdata

    print("AddRoundKey step:")
    assertdata = cryptoprovider._blocks[0]._blockdata
    cryptoprovider._addroundkey(0)
    cryptoprovider._round += 1
    printcryptoblocks(cryptoprovider)
    print("AddRoundKey_inv step:")
    cryptoprovider._addroundkey(0)
    cryptoprovider._round -= 1
    printcryptoblocks(cryptoprovider)
    assert cryptoprovider._blocks[0]._blockdata == assertdata

    print("Encrypt:")
    cryptoprovider.encrypt()
    printcryptoblocks(cryptoprovider)
    print("Decrypt:")
    cryptoprovider.decrypt()
    printcryptoblocks(cryptoprovider)
    assert cryptoprovider.getcipher() == ba

    print("Rijndael (Rijndael): All tests passed.")


def printcryptoblocks(cp):
    print(repr(cp))
    for block in cp._blocks:
        print(repr(block))
        print(block)


if __name__ == '__main__':
    main()
