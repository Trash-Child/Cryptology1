from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter 

# Random Key Generator
def KeyGen():
    """Returns random key of 128 bits"""
    # interval [0, 2^128-1]

    key = get_random_bytes(16)
    return key

# Hash function
def NMAC(msg,k1,k2):
    
    # Generate digests
    
    h1 = SHA256.new(k1 + msg) 
    h2 = SHA256.new(k2 + h1.digest())
    return h2.hexdigest()

# Padding Algorithm
def PKCS5Padding(message):
    """Padding algorithm PKCS #5:
    Padding of messages to recieve length multiple of B = 128"""

    B = 128
    l = len(message)
    lHat = [0]

    # Solving eq for l^ : B = 8*(l+lHat)
    # we assume that message length will be in range [B, 99·B]
    for i in range(1,100):
        if i*B - 8*l < 0:
            continue
        else:
            if (i*B - 8*l) % 8 == 0 :
                lHat[0] = (i*B-8*l) // 8
                break

    print("lHat", lHat[0])

    # computing binary representation with 8 bits
    lHatBin = bytearray(lHat)
    print(lHatBin)

    # padding the message with the binary representation of [l^] l^-times 
    paddedMessage = message
    for _ in range(lHat[0]):
        paddedMessage += lHatBin

    if len(paddedMessage) % 16 != 0:
        print("ERROR in padding - not multiple of B")
        assert False, 'Padded message not a multiple of B, length: ' + str(len(paddedMessage))

    print(paddedMessage)
    return paddedMessage


# put the encr and decr functions here

# Generate keys and message
key1 = KeyGen()
key2 = KeyGen()
message = "hello there! how are you doing today? do you want to drink a coffee later?"

# "send" message

# Call test

# Manipulate message (ciphertext)

# Call test - NMAC check should fall here


def Test(): #ciphertext, original message

    # Enctrypt message
    # Create NMAC

    # Check NMAC against new NMAC, if true proceed, otherwise report

    # Decrypt
    # Check decryption
    # Report success


def checkResult(): #Decrypted msg, original msg
    # If statement - decrypted message vs original
