from Crypto.Cipher import AES
from des import DesKey
import blowfish
from twofish import Twofish
from base64 import b64encode
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes




def runAES(text):  

    print("\nAES Encryption\n")
    
    # fetching random sequence of bytes to be used as key and initialization vector

    key = get_random_bytes(32)          # 32 length byte string is used as key
    iv = get_random_bytes(16)           # 16 length byte string is used as iv
    mode = AES.MODE_CBC

    # creating the encryption and decryption ciphers
    cipher_enc = AES.new(key, mode, iv)
    cipher_dec = AES.new(key, mode, iv)
    text=pad(text,16)
    

    
    encrypted = cipher_enc.encrypt(text)        
    print("Encrypted Text is: ", b64encode(encrypted).decode("utf-8"))   
    decrypted = cipher_dec.decrypt(encrypted)
    decrypted=unpad(decrypted,16)
    print("Decrypted Text is: ", decrypted.decode("utf-8"))
        
    
    


def runDES(text):
    
    def DES(text):

        print("\n\nDES Encryption\n")
        key0 = DesKey(get_random_bytes(8))
        
        encrypted=key0.encrypt(text, padding = True)
        print("Encrypted Text is:", b64encode(encrypted).decode("utf-8"))
        
        decrypted=key0.decrypt(encrypted, padding = True)
        print("Decrypted Text is:", decrypted.decode("utf-8"))
        
        

    def TripleDES(text):

        print("\n\nTripleDES Encryption\n")
        key1 = DesKey(get_random_bytes(24))

        encrypted = key1.encrypt(text, padding = True)
        print("Encrypted Text is:", b64encode(encrypted).decode("utf-8"))
        
        decrypted = key1.decrypt(encrypted, padding = True)
        print("Decrypted Text is:", decrypted.decode("utf-8"))
        
        
    

    DES(text)
    TripleDES(text)
        
        
def runBlowfish(text):

    print("\n\nBlowfish Encryption\n")
    cipher = blowfish.Cipher(get_random_bytes(24))
    iv = get_random_bytes(8) # initialization vector
    
    
    

    text=pad(text,8)
    


    data_encrypted = b"".join(cipher.encrypt_cbc(text, iv))
    data_decrypted = b"".join(cipher.decrypt_cbc(data_encrypted, iv))
    data_decrypted=unpad(data_decrypted,8)
    

    print("Encrypted Text is:", b64encode(data_encrypted).decode("utf-8"))
    print("Decrypted Text is:", data_decrypted.decode())
    
    
def runTwofish(text):

    print("\n\nTwofish Encryption\n")
    
    text=pad(text,16)
        

    key = get_random_bytes(32)
    T = Twofish(key)                # creating a Twofish object
    encrypted = T.encrypt(text)
    decrypted=T.decrypt(encrypted)
    
    decrypted=unpad(decrypted,16)
    

    print("Encrypted Text is:", b64encode(encrypted).decode("utf-8"))
    print("Decrypted Text is:", decrypted.decode(), "\n")


# Calling all the encryption functions
def main():

    text=input("\nEnter Text to be Encrypted: ")
    #print(len(text))
    b_text=bytes(text, "utf-8")

    #runAES(b_text)
    #runDES(b_text)
    #runBlowfish(b_text)
    runTwofish(b_text)
    print("\n\n")
    
    

main()
