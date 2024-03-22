from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter 

from random import randint
import operator

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

    # creating nonce
    r = []
    for i in range(16):
        r.append(randint(0,2**8))
    r = bytearray(r)
    # inital nonce value
    r0 = r

    # counter mode using ECB AES to encrypt one block
    for i in range(l):
        # constructing AES encryption cipher in Counter Mode from key
        cipher = AES.new(key, AES.MODE_ECB)

        # computing the F(k,r) block from CTR mode
        Fkr = cipher.encrypt(r)
        
        # now encrypting the message by: F(k,r) xor Message
        int_cipherBlock = [0]*16
        int_Fkr = list(Fkr)
        int_byteMessage = list(byteMessage[16*i:16*i+16])

        for j in range(16):
            int_cipherBlock[j] = operator.xor(int_Fkr[j], int_byteMessage[j])
        cipherBlock = bytearray(int_cipherBlock)

        cipherText += cipherBlock

        # update r: r = r+1 
        int_r = list(r)
        int_r[15] += 1
        for j in range(15,-1,-1):
            if int_r[j] >= 2**8:
                if j != 15:
                    int_r[j+1] += 1
            else: 
                break
        r = bytearray(int_r)

    print("cipherText", cipherText)

    return r0, key, cipherText


def Dec(key, cipherText, r0):
    """Decryption of a ciphertext using AES encryption in CTR mode"""

    decMessage = bytes(0)
    l = len(cipherText)//16

    # set intial nonce as
    r = r0

    # counter mode using ECB AES to encrypt one block
    for i in range(l):
        # constructing AES encryption cipher in Counter Mode from key
        cipher = AES.new(key, AES.MODE_ECB)

        # computing the F(k,r) block from CTR mode
        Fkr = cipher.encrypt(r)
        
        # now encrypting the message by: F(k,r) xor Message
        int_messageBlock = [0]*16
        int_Fkr = list(Fkr)
        int_messageBlock = list(cipherText[16*i:16*i+16])

        for j in range(16):
            int_messageBlock[j] = operator.xor(int_Fkr[j], int_messageBlock[j])
        messageBlock = bytearray(int_messageBlock)

        decMessage += messageBlock

        # update r: r = r+1 
        int_r = list(r)
        int_r[15] += 1
        for j in range(15,-1,-1):
            if int_r[j] >= 2**8:
                if j != 15:
                    int_r[j+1] += 1
            else: 
                break
        r = bytearray(int_r)

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

