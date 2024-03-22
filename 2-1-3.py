from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter 
# Import our other files
import aes_counter_enc as our_aes
import NMAC as our_nmac

def Test(ciphertext, mac, orig_msg, r0): #ciphertext, original message

    rec_ctxt, rec_mac = ciphertext, mac         # "Receive" message
    if (checkMac(rec_ctxt, rec_mac) == 0 ):     # If mac check fails, stop
        return 0                    
    
    dec_msg = our_aes.Dec(key1,rec_ctxt, r0)        # Decrypt
    if (checkResult(dec_msg, orig_msg) == 0):
        return 0
    
    print("Message received succesfully!")      # Show result
    print_msg = str(dec_msg, "UTF-8")
    print("Message: " + print_msg)

def checkMac(ctxt, mac): #Decrypted msg, original msg
    if (mac == our_nmac.NMAC(ctxt, key1, key2)):
        print("MAC ok, proceed to decryption... ")
        return 1
    else:
        print("MAC check failed, abort!")
        return 0
    
def checkResult(dec_msg, orig_msg):
    if(dec_msg == bytes(orig_msg,"UTF-8")):
        print("Decryption succesful!")
        return 1
    else:
        print("Decryption failed")
        return 0


print("| \n| \n| TESTING in exercise 2.1.3 \n| \n|")
# Generate keys and message
key1 = our_aes.KeyGen()
key2 = our_aes.KeyGen()
mymessage = "hello there! how are you doing today? do you want to drink a coffee later?"
bytemessage=bytearray(mymessage,"UTF-8")
# encrypt and construct NMAC
alice_ctxt = our_aes.Enc(bytemessage, key1)

byte_alice_ctxt = bytearray(alice_ctxt[2])
alice_nmac = our_nmac.NMAC(byte_alice_ctxt, key1, key2)
r0 = alice_ctxt[0]
# Test before attack - should succeed
print("| \n| Running test without attack 2.1.3 \n|")
Test(byte_alice_ctxt, alice_nmac, mymessage, r0)

# Attack ciphertext
byte_alice_ctxt = byte_alice_ctxt + bytearray(0b00011010010010)
print("| \n| Running test after attack 2.1.3 \n|")
# Test after attack - should fail on NMAC-check
Test(byte_alice_ctxt, alice_nmac, mymessage, r0)









