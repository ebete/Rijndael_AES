import sys
import base64
import argparse
from Rijndael import Rijndael


# Main entry point.
def main():
    parser = argparse.ArgumentParser(description="Rijndael cipher implementation in Python.")
    parser.add_argument("-s", "--state-size", metavar="bits", help="The state size to use in bits", action="store", type=int, default=128)
    parser.add_argument("-k", "--key-size", metavar="bits", help="The key size to use in bits", action="store", type=int, default=128)
    parser.add_argument("-p", "--passkey", metavar="key", help="The secret key to use", action="store", type=str, required=True)
    parser.add_argument("-i", "--input", metavar="input", help="The input text to process", action="store", type=str, default=sys.stdin)
    args = parser.parse_args()

    plaintext = args.input
    secret = args.passkey
    statesize = args.state_size
    keysize = args.key_size

    cryptoprovider = Rijndael(statesize, keysize)
    cryptoprovider.createdatablocks(plaintext)
    encdata = cryptoprovider.getcipher()
    print("Plaintext string:")
    print(base64.b64encode(encdata).decode('ascii'))

    cryptoprovider.setencryptionkey(secret)
    cryptoprovider.encrypt()
    encdata = cryptoprovider.getcipher()
    print("Encrypted string:")
    print(base64.b64encode(encdata).decode('ascii'))

    cryptoprovider.decrypt()
    encdata = cryptoprovider.getcipher()
    print("Decrypted string:")
    print(base64.b64encode(encdata).decode('ascii'))


if __name__ == '__main__':
    main()
