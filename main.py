import sys
import base64
from Rijndael import Rijndael


# Main entry point.
def main(argv):
    ao = 0
    if len(argv) > 3:
        plaintext = str(argv[0])
        ao = 1
    else:
        plaintext = ""
        for line in sys.stdin:
            plaintext += line
    secret = str(argv[0+ao])
    statesize = int(argv[1+ao])
    keysize = int(argv[2+ao])

    cryptoprovider = Rijndael(statesize, keysize)
    cryptoprovider.createdatablocks(plaintext)
    cryptoprovider.setencryptionkey(secret)
    cryptoprovider.encrypt()
    encdata = cryptoprovider.getcipher()

    print(base64.b64encode(encdata).decode('ascii'))


if __name__ == '__main__':
    main(sys.argv[1:])
