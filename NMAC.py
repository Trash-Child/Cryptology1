# A2, Ex 2.1.2
####################

from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

msg = "HelloWorld"

# Define functions

def KeyGen(): # Same keygen function as in 2.1.1
    """Returns random key of 128 bits"""
    # interval [0, 2^128-1]

    key = get_random_bytes(16)
    return key

def NMAC(msg,key1,key2):
    k1 = bytearray(key1)
    k2 = bytearray(key2)

    # Generate digests
    h1 = SHA256.new(k1 + msg) 
    h2 = SHA256.new(k2 + h1.digest())
    return h2.hexdigest()



# Test 
"""
# Generate keys
key1 = bytearray(KeyGen())
key2 = bytearray(KeyGen())

# Sender
aliceMsg = "HelloBob"
aliceHash = NMAC(bytearray(aliceMsg,'UTF-8'),key1,key2)
print("Message = ",aliceMsg)
print("Hexdigest = ", aliceHash)

# Potential adversary - modifying the message
# comment out to remove attack
aliceMsg = "HelloAdam"


#Receiver
recMsg = aliceMsg
recHash = aliceHash




if (recHash == NMAC(bytearray(recMsg,'UTF-8'),key1,key2)):
    print("message accepted, received:")
    print("Message = ",recMsg)
    print("Hexdigest = ",recHash)
else: print("Message not accepted")




"""

