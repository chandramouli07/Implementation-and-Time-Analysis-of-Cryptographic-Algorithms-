from Crypto.Cipher import AES
from des import DesKey
import blowfish
from twofish import Twofish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import timeit
import matplotlib.pyplot as plt


def runAES(text):  
    
    # fetching random sequence of bytes to be used as key and initialization vector

    key = get_random_bytes(32)          # 32 length byte string is used as key
    iv = get_random_bytes(16)           # 16 length byte string is used as iv
    mode = AES.MODE_CBC

    # creating the encryption and decryption ciphers
    cipher_enc = AES.new(key, mode, iv)
    cipher_dec = AES.new(key, mode, iv)
    text=pad(text,16)
    encrypted = cipher_enc.encrypt(text)

    return cipher_enc,cipher_dec,text,encrypted

def AES_TimeAnalysis():
    
    print('\nAES:')

    setup_code = '''
    
from __main__ import runAES
from __main__ import b_text
    
cipher_enc,cipher_dec,text,encrypted=runAES(b_text)'''
    
    statement1 = '''cipher_enc.encrypt(text)'''
    statement2 = '''cipher_dec.decrypt(encrypted)'''
    
    aes_encTime = timeit.timeit(setup = setup_code, stmt = statement1, number = 100)
    aes_decTime = timeit.timeit(setup = setup_code, stmt = statement2 , number = 100)

    print(f"Encryption time of AES is: {aes_encTime}")
    print(f"Decryption time of AES is: {aes_decTime}")

    return aes_encTime, aes_decTime


def runDES(text):

        key0 = DesKey(get_random_bytes(8))
        encrypted=key0.encrypt(text, padding = True)

        return key0,encrypted
    
def DES_TimeAnalysis():

    print("\nDES:")

    setup_code = '''
from __main__ import runDES
from __main__ import b_text

key0,encrypted=runDES(b_text)'''

    statement1 = '''key0.encrypt(b_text, padding = True)'''
    statement2 = '''key0.decrypt(encrypted, padding = True)'''

    des_encTime = timeit.timeit(setup = setup_code, stmt = statement1 , number = 100)
    des_decTime = timeit.timeit(setup = setup_code, stmt = statement2 , number = 100)
    
    print(f"Encryption time of DES is: {des_encTime}")
    print(f"Decryption time of DES is: {des_decTime}")

    return des_encTime, des_decTime


def TripleDES(text):

        key1 = DesKey(get_random_bytes(24))
        encrypted = key1.encrypt(text, padding = True)        

        return key1,encrypted

def TripleDES_TimeAnalysis():

    print("\nTriplesDES:")

    setup_code = '''
from __main__ import TripleDES
from __main__ import b_text
key1,encrypted=TripleDES(b_text)'''
    
    statement1 = '''key1.encrypt(b_text, padding = True)'''
    statement2 = '''key1.decrypt(encrypted, padding = True)'''

    tdes_encTime = timeit.timeit(setup = setup_code, stmt = statement1, number = 100)
    tdes_decTime = timeit.timeit(setup = setup_code, stmt = statement2, number = 100)
    
    print(f"Encryption time of TripleDES is: {tdes_encTime}")
    print(f"Decryption time of TripleDES is: {tdes_decTime}")

    return tdes_encTime, tdes_decTime


def runBlowfish(text):

    cipher = blowfish.Cipher(get_random_bytes(24))
    iv = get_random_bytes(8) # initialization vector
    text=pad(text,8)
    data_encrypted = b"".join(cipher.encrypt_cbc(text, iv))
        
    return cipher,iv,text,data_encrypted

def Blowfish_TimeAnalysis():

    print("\nBlowfish:")

    setup_code = '''
from __main__ import runBlowfish
from __main__ import b_text

cipher,iv,text,data_encrypted=runBlowfish(b_text)'''

    statement1 = '''cipher.encrypt_cbc(text, iv)'''
    statement2 = '''cipher.decrypt_cbc(data_encrypted, iv)'''

    bl_encTime = timeit.timeit(setup = setup_code, stmt = statement1, number = 100)
    bl_decTime = timeit.timeit(setup = setup_code, stmt = statement2, number = 100)
    
    print(f"Encryption time of Blowfish is: {bl_encTime}")
    print(f"Decryption time of Blowfish is: {bl_decTime}")

    return bl_encTime, bl_decTime


def runTwofish(text):
    
    text = pad(text, 16)

    key = get_random_bytes(32   )
    T = Twofish(key)                # creating a Twofish object
    encrypted = T.encrypt(text)
    
    return key,T,text,encrypted

def Twofish_TimeAnalysis():

    print("\nTwofish:")
    
    setup_code = '''
from __main__ import runTwofish
from __main__ import b_text

key,T,text,encrypted=runTwofish(b_text)'''
    
    statement1='''T.encrypt(text)'''
    statement2='''T.decrypt(encrypted)'''

    tw_encTime = timeit.timeit(setup = setup_code, stmt = statement1, number = 100)
    tw_decTime = timeit.timeit(setup = setup_code, stmt = statement2, number = 100)
    
    print(f"Encryption time of Twofish is: {tw_encTime}")
    print(f"Decryption time of Twofish is: {tw_decTime}")

    return tw_encTime, tw_decTime
    

def time_LineGraph(x, y):

    plt.plot(x, y)
    plt.xlabel('Algorithm')
    plt.ylabel('Execution Time')

    if y[0] == aesEncTime:
        plt.title('Encryption time comparison')
        plt.savefig("Encryption time comparison - Blowfish and Twofish.png")
    elif y[0] == aesDecTime:
        plt.title('Decryption time comparison')
        plt.savefig("Decryption time comparison - Blowfish and Twofish.png")

    plt.show()
    


def encTimeVsBlockSize():

    plt.plot(blockSize, aesEncTimes, color = 'green', label = 'AES')
    plt.plot(blockSize, desEncTimes, color = 'blue', label = 'DES')
    plt.plot(blockSize, tdesEncTimes, color = 'yellow', label = '3DES')
    plt.plot(blockSize, blEncTimes, color = 'red', label = 'Blowfish')

    plt.xlabel('Input Block Size')
    plt.ylabel('Encryption Time')
    plt.title('Encryption time vs Input block size')
    plt.legend()
    plt.savefig("encTimeVsBlockSize.png")
    plt.show()
    

def decTimeVsBlockSize():

    plt.plot(blockSize, aesDecTimes, color = 'green', label = 'AES')
    plt.plot(blockSize, desDecTimes, color = 'blue', label = 'DES')
    plt.plot(blockSize, tdesDecTimes, color = 'yellow', label = '3DES')
    plt.plot(blockSize, blDecTimes, color = 'red', label = 'Blowfish')

    plt.xlabel('Input Block Size')
    plt.ylabel('Decryption Time')
    plt.title('Decryption time vs Input block size')
    plt.legend()
    plt.savefig("decTimeVsBlockSize.png")
    plt.show()
    

def Encryption_aesVsblowfish():

    #plt.plot(blockSize, aesEncTimes, color = 'green', label = 'AES')
    plt.plot(blockSize, blEncTimes, color = 'red', label = 'Blowfish')
    
    plt.xlabel('Input Block Size')
    plt.ylabel('Encryption Time')
    plt.title('AES vs Blowfish Comparison: Encryption time-input block size')
    plt.legend()
    plt.savefig("Encryption_aesVsblowfish.png")
    plt.show()
    

def Decryption_aesVsblowfish():

    #plt.plot(blockSize, aesDecTimes, color = 'green', label = 'AES')
    plt.plot(blockSize, blDecTimes, color = 'red', label = 'Blowfish')

    plt.xlabel('Input Block Size')
    plt.ylabel('Decryption Time')
    plt.title('AES vs Blowfish Comparison: Decryption time-input block size')
    plt.legend()
    plt.savefig("Decryption_aesVsblowfish.png")
    plt.show()
    

def Encryption_desVs3des():

    plt.plot(blockSize, desDecTimes, color = 'blue', label = 'DES')
    plt.plot(blockSize, tdesDecTimes, color = 'yellow', label = '3DES')

    plt.xlabel('Input Block Size')
    plt.ylabel('Encryption Time')
    plt.title('DES vs 3DES Comparison: Encryption time-input block size')
    plt.legend()
    plt.savefig("Encryption_desVs3des.png")
    plt.show()
    

def Decryption_desVs3des():

    plt.plot(blockSize, desDecTimes, color = 'blue', label = 'DES')
    plt.plot(blockSize, tdesDecTimes, color = 'yellow', label = '3DES')

    plt.xlabel('Input Block Size')
    plt.ylabel('Decryption Time')
    plt.title('DES vs 3DES Comparison: Decryption time-input block size')
    plt.legend()
    plt.savefig("Decryption_desVs3des.png")
    plt.show()
    


text = input("\nEnter Text to be Encrypted: ")
b_text = bytes(text, "utf-8")

aesEncTime, aesDecTime = AES_TimeAnalysis()  
desEncTime, desDecTime = DES_TimeAnalysis()
tdesEncTime, tdesDecTime = TripleDES_TimeAnalysis()
blEncTime, blDecTime = Blowfish_TimeAnalysis()
#twEncTime, twDecTime = Twofish_TimeAnalysis()
print()

x = ['AES', 'DES', '3DES', 'Blowfish']
#x1=["Blowfish","Twofish"]
#y1_enc=[blEncTime,twEncTime]
#y1_dec=[blDecTime,twDecTime]
y_enc = [aesEncTime, desEncTime, tdesEncTime, blEncTime]
y_dec = [aesDecTime, desDecTime, tdesDecTime, blDecTime]
time_LineGraph(x, y_enc)
time_LineGraph(x, y_dec)

time_LineGraph(x1, y1_enc)
time_LineGraph(x1, y1_dec)


blockSize = [16, 32, 64, 128, 256]

aesEncTimes = []
aesDecTimes = []
desEncTimes = []
desDecTimes = []
tdesEncTimes = []
tdesDecTimes = []
blEncTimes = []
blDecTimes = []

t=''
for i in range(5):
    t = text * 2**i
    b_text = bytes(t, 'utf-8')
    
    print('\nText to be encrypted:\n', t, '\n')
    print("Length of text:",len(t))
    aesEncTime, aesDecTime = AES_TimeAnalysis()  
    desEncTime, desDecTime = DES_TimeAnalysis()
    tdesEncTime, tdesDecTime = TripleDES_TimeAnalysis()
    blEncTime, blDecTime = Blowfish_TimeAnalysis()

    aesEncTimes.append(aesEncTime)
    aesDecTimes.append(aesDecTime)
    desEncTimes.append(desEncTime)
    desDecTimes.append(desDecTime)
    tdesEncTimes.append(tdesEncTime)
    tdesDecTimes.append(tdesDecTime)
    blEncTimes.append(blEncTime)
    blDecTimes.append(blDecTime)


encTimeVsBlockSize()
decTimeVsBlockSize()
Encryption_aesVsblowfish()
Decryption_aesVsblowfish()
Encryption_desVs3des()
Decryption_desVs3des()
