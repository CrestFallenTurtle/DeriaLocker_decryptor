from hashlib import sha512
from array import array as Array
from argparse import ArgumentParser
from os.path import exists
from sys import exit
from os import stat

try:
    from Crypto.Cipher import AES
except ImportError:
    exit("Failed to import 'Crypto', run 'python3 -m pip install pycryptodome' to install it")

KEY = [] # Integer values
HEX_KEY = "" # Hex representation

IV = [] # Integer values
HEX_IV = "" # Hex representation

PASS = "b3f6c3r6vctb9c3n789um83zn8c3tb7c3brc3b5c77327tbrv6b123rv6c3rb6c7tc3n7tb6tb6c3t6b35nt723472357t1423tb231br6c3v4"

FILE = ""

LOGO = '''
______          _       _                _                   _                            _             
|  _  \        (_)     | |              | |                 | |                          | |            
| | | |___ _ __ _  __ _| |     ___   ___| | _____ _ __    __| | ___  ___ _ __ _   _ _ __ | |_ ___  _ __ 
| | | / _ | '__| |/ _` | |    / _ \ / __| |/ / _ | '__|  / _` |/ _ \/ __| '__| | | | '_ \| __/ _ \| '__|
| |/ |  __| |  | | (_| | |___| (_) | (__|   |  __| |    | (_| |  __| (__| |  | |_| | |_) | || (_) | |   
|___/ \___|_|  |_|\__,_\_____/\___/ \___|_|\_\___|_|     \__,_|\___|\___|_|   \__, | .__/ \__\___/|_|   
                                                                               __/ | |                  
                                                                              |___/|_|                  
'''

def upper_bound(array:list) -> int:
    """
    Description: Calculates the upperbound of a list, aka the pos of the last element
    Input:
        - array (list) The list to utilize

    Return: The index
    """
    return len(array) -1

def lower_bound(array:list) -> int:
    """
    Description: Calculates the lower bound of a list, aka the pos of the first element
    Input:
        - array (list) The list to utilize

    Return: The index
    """
    return 0

def CreateKey(strPassword:str) -> list[bytes]:
    """
    Description: Generates the Key portion based on the password
    Input:
        - strPassword (str) The password to generate Key from
    Return:
        - A list containing byte data representing the generated Key
    """
    array = [char for char in strPassword] # Convert to char array
    upperBound = upper_bound(array)
    array2 = [bytes(0) for _ in range(0,upperBound+1)]
    arg_25_0 = 0
    upperBound2 = upper_bound(array)
    num = arg_25_0
    num2 = 0    

    while (True):
        arg_46_0 = num
        num2 = upperBound2
        
        if (arg_46_0 > num2):
            break

        array2[num] = ord(array[num])
        num += 1

    array3 = sha512(Array("B", array2)).digest()
    array4 = [bytes(0) for _ in range(0,32)]
    num3 = 0
    arg_7A_0 = 0
    
    
    while (arg_7A_0 <= num2):
        array4[num3] = array3[num3]
        num3 += 1
        arg_7A_0 = num3
        num2 = 31

    return array4

def CreateIV(strPassword:str) -> list[bytes]:
    """
    Description: Generates the IV portion based on the password
    Input:
        - strPassword (str) The password to generate IV from
    Return:
        - A list containing byte data representing the generated IV
    """
    array = [char for char in strPassword] # Convert to char array
    upperBound = upper_bound(array)
    array2 = [bytes(0) for _ in range(0,upperBound+1)]
    arg_25_0 = 0
    upperBound2 = upper_bound(array)
    num = arg_25_0
    num2 = 0

    while (True):
        arg_46_0 = num
        num2 = upperBound2
        if (arg_46_0 > num2):
            break

        array2[num] = ord(array[num])
        num += 1

    array3 = sha512(Array("B", array2)).digest()
    array4 = [bytes(0) for _ in range(0,16)]
    
    num3 = 32
    arg_7E_0 = 0
    
    while (arg_7E_0 <= num2):
        array4[num3 - 32] = array3[num3]
        num3 += 1
        arg_7E_0 = num3
        num2 = 47

    return array4

def Decrypt_file(path_to_encrypted_file:str) -> bool:
    """
    Description: Tries to decrypt the provided file.
    Input:
        - path_to_encrypted_file (str) The path to the file you want to decrypt
    Return:
        - If it succeeds then a True will be returned, else False
    """
    global HEX_KEY, HEX_IV
    toReturn = False
    num = 0
    length = stat(path_to_encrypted_file).st_size

    output_file = path_to_encrypted_file.replace(".deria", "", -1) # Grab the "decrypted" name

    try:
        encrypted_file = open(path_to_encrypted_file, "rb")
        decrypted_file = open(output_file, "wb")
        cipher = AES.new(HEX_KEY, AES.MODE_CBC, HEX_IV)

        while (num < length):
            line = encrypted_file.read(4096)
            num2 = len(line)
            
            decrypted_line = cipher.decrypt(line)
            decrypted_file.write(decrypted_line)
            num += num2
        
        decrypted_file.close()
        encrypted_file.close()

        print(f"[~] The decrypted file can be found at '{output_file}'")
        toReturn = True

    except Exception as err:
        print(f"[!] An error occurred during decrypt, {err}")



    return toReturn


if __name__ == "__main__":
    args = ArgumentParser("Decryptor for the DeriaLocker ransomware")
    args.add_argument("-file", help="Path to the encrypted file", required=True)
    args.add_argument("-key", help="Key to use, the program will generate it's own version if it's not supplied. Must be in byte format!")
    args.add_argument("-iv", help="The found IV, the program will generate it's own version if it's not supplied. Must be in byte format!")
    args.add_argument("-password", help="The utilized password, this can be used to generate the key and iv")

    args = args.parse_args()
    
    print(LOGO)

    if args.key:
        HEX_KEY = args.key

    if args.iv:
        HEX_IV = args.iv

    if args.password:
        PASS = args.password


    if len(KEY) == 0 and len(HEX_KEY) == 0: # Nothing was provided
        KEY = CreateKey(PASS)
        HEX_KEY = bytes(KEY)
    
    if len(IV) == 0 and len(HEX_IV) == 0: # Nothing was provided
        IV = CreateIV(PASS)
        HEX_IV = bytes(IV)

    FILE = args.file # Our path

    if not exists(FILE):
        exit(f"[!] Failed to find file '{FILE}'")

    if not str(FILE).endswith("deria"):
        print(f"[!] The file, '{FILE}', is not a valid one as it doesn't end with '.deria'.")
        print("[!] Will still continue to decrypt but there is no guarantees")

    print(f"[~] Decrypting file '{FILE}'")    

    print(f"[~] Utilizing password '{PASS}'")

    print(f"\n[~] Utilizing key..")
    print(f"\t* Integer representation '{KEY}'")
    print(f"\t* Hex representation '{HEX_KEY}'")
    print(f"\t* Length '{len(HEX_KEY)}'")

    print(f"\n[~] Utilizing IV..")
    print(f"\t* Integer representation '{IV}'")
    print(f"\t* Hex representation '{HEX_IV}'")
    print(f"\t* Length '{len(HEX_IV)}'")


    print("\n[~] Trying to decrypt file..")
    
    if (Decrypt_file(FILE)):
        print("[~] Successfully decrypted the target file!")
    else:
        print("[!] Failed to decrypt the target file!")