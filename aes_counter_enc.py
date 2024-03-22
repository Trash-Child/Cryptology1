from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter 

from random import randint

####################
## Exercise 2.1.1 ##
####################

def KeyGen():
    """Returns random key of 128 bits"""
    # interval [0, 2^128-1]

    key = get_random_bytes(16)
    return key

def PKCS5Padding(message):
    """Padding algorithm PKCS #5:
    Padding of messages to recieve length multiple of B = 128"""

    B = 128
    l = len(message)

    # Solving eq for l^ : B = 8*(l+lHat)
    # we assume that message length will be in range [B, 99·B]
    for i in range(1,100):
        if i*B - 8*l < 0:
            continue
        else:
            if (i*B - 8*l) % 8 == 0 :
                lHat = (i*B-8*l) // 8
                break

    # computing binary representation with 8 bits
    lHatBin = bytearray([lHat])
    print(lHatBin)

    # padding the message with the binary representation of [l^] l^-times 
    paddedMessage = message
    for _ in range(lHat):
        paddedMessage += lHatBin

    if len(paddedMessage) % 16 != 0:
        print("ERROR in padding - not multiple of B")
        assert False, 'Msg not a multiple of B, length: ' + str(len(paddedMessage))

    print(paddedMessage)
    return paddedMessage


def Enc(message, key):
    """Encryption of a message using AES encryption in CTR mode"""
    B_bytes = 128/8

    # padding of message
    byteMessage = PKCS5Padding(message)

    # computing number of blocks
    l = len(byteMessage)//16

    # initalize bytes
    cipherText = bytes(0)
    r0 = randint(0,2**128)

    # create a counter for the AES encryption
    count = Counter.new(128, initial_value=r0)

    # counter mode
    for i in range(l):
        # constructing AES encryption cipher in Counter Mode from key
        cipher = AES.new(key, AES.MODE_CTR, counter=count)

        # encrypt one block (128/8 = 16 bytes) at a time using the cipher
        cipherBlock = cipher.encrypt(byteMessage[16*i:16*i+16])

        cipherText += cipherBlock

    print(cipherText)
    return r0, key, cipherText


def Dec(key, cipherText, r0):
    """Decryption of a ciphertext using AES encryption in CTR mode"""

    decMessage = bytes(0)
    l = len(cipherText)//16

    # create a counter for the AES encryption
    count = Counter.new(128, initial_value=r0)

    # counter mode 
    for i in range(l):
        # constructing AES encryption cipher in Counter Mode from key
        cipher = AES.new(key, AES.MODE_CTR, counter=count)

        # decrypt one block (128/8 = 16 bytes) at a time using the cipher
        msgBlock = cipher.decrypt(cipherText[16*i:16*i+16])

        # concatenate and transforms to interger array
        decMessage += msgBlock

    # depadding 
    padding = decMessage[len(decMessage)-1]
    returnMessage = decMessage[0:len(decMessage)-padding]

    return returnMessage


# --------------------------------------
# testing encryption and decryption

if __name__ == '__main__':
    # test message - long enough to cause multiple blocks
    message = "hello there! how are you doing today? do you want to drink a coffee later?"
    enc_msg = message.encode()
    print(message, len(message), type(message))

    # generating a random key
    key = KeyGen()

    r0, key, cipherText = Enc(enc_msg, key)
    dec_msg = Dec(key, cipherText, r0)

    dec_str_msg = dec_msg.decode()

    if message == dec_str_msg:
        print("SUCCESS!!")
        print("message:", message)
        print("decoded msg:", dec_msg.decode())
    else:
        print("MESSAGE LOST")
        print("message:", message)
        print("decoded msg:", dec_msg.decode())

