from hashlib import pbkdf2_hmac
import random

def create_aadhash(hashnt=None,iteration = 1000,):
    # literal convert powershell to python script :
    # https://github.com/Gerenios/AADInternals/blob/b135545d50a5a473c942139182265850f9d256c2/AzureADConnectAPI_utils.ps1#L279

    hashbytes = bytearray(hashnt.encode('UTF-16LE'))

    listnb = []
    while not len(listnb) >= 10 :
        listnb.append(random.choice(list(range(0, 256))))

    salt = bytearray(listnb)
    #salt = bytearray([180 ,119 ,18 ,77 ,229 ,76 ,32 ,48 ,55 ,143])

    salthex = salt.hex()
    key = pbkdf2_hmac("sha256", hashbytes, salt, iteration, 32).hex()
    aadhash = "v1;PPH1_MD4,%s,%s,%s;" % (salthex,iteration,key)
    return aadhash


