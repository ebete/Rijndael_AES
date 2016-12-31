import sys
import base64
import argparse
from Rijndael import Rijndael


# Main entry point.
def main():
    parser = argparse.ArgumentParser(description="Rijndael cipher implementation in Python.")
    parser.add_argument("-d", "--decrypt", help="Switch to decryption mode", action="store_true")
    parser.add_argument("-s", "--state-size", metavar="bits", help="The state size to use in bits", action="store", type=int, default=128)
    parser.add_argument("-k", "--key-size", metavar="bits", help="The key size to use in bits", action="store", type=int, default=128)
    parser.add_argument("-f", "--file-input", metavar="FILE", help="The input file to process (stdin is default)", action="store", nargs='?', type=argparse.FileType('r'), default=sys.stdin)
    parser.add_argument("-i", "--text-input", metavar="KEY", help="The input text to process (overwrites file input)", action="store", type=str)
    parser.add_argument("-p", "--passkey", metavar="KEY", help="The secret key to use", action="store", type=str, required=True)
    args = parser.parse_args()

    plaintext = ""
    if args.text_input is None:
        infile = args.file_input
        for line in infile:
            plaintext += line
    else:
        plaintext = args.text_input
    secret = args.passkey
    statesize = args.state_size
    keysize = args.key_size
    mode_decrypt = args.decrypt

    cryptoprovider = Rijndael(statesize, keysize)
    cryptoprovider.createdatablocks(plaintext)
    cryptoprovider.setencryptionkey(secret)
    if mode_decrypt:
        cryptoprovider.decrypt()
    else:
        cryptoprovider.encrypt()
    encdata = cryptoprovider.getcipher()
    print(base64.b64encode(encdata).decode('ascii'))


if __name__ == '__main__':
    main()
