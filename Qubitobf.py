from Crypto.Cipher import AES
import argparse
import base64
import random 
import string
import sys

def generate_random_string(length):
    letters_and_digits = string.ascii_letters 
    result = ''.join((random.choice(letters_and_digits) for i in range(length)))
    return result
    
def obfuscate(body):
    obfuscated = ""
    for i in body :
        if obfuscated == "" :
            obfuscated += "chr(" + str(ord(i)) + ")"
        else :
            obfuscated += "+" + "chr(" + str(ord(i)) + ")"
    return "exec(" + obfuscated + ")"
    
def convert_source_to_encrypted_source_code(source_code):
    print("[+] converting source_code to base64 ...")
    base64_source_code = base64.b64encode(source_code.encode())
    print("[+] source code convert to base64 successfully :)")
    print("[+] calculating pad for AES Encrtyption ...")
    pad = generate_random_string(16 - len(base64_source_code)%16)
    print("[+] pad is : " + pad)
    print("[+] Adding pad to source code ...")
    base64_source_code_with_pad = base64_source_code + pad.encode()
    print("[+] generating random AES key ...")
    AES_key = generate_random_string(16).encode("utf8")
    print("[+] AES KEY is : " + AES_key.decode() )
    print("[+] generating random AES IV ...")
    AES_iv = generate_random_string(16).encode("utf8")
    print("[+] AES IV is : " + AES_iv.decode() )
    AES_obj = AES.new(AES_key, AES.MODE_CBC, AES_iv)
    print("[+] encrypting source code ...")
    enc_source_code = AES_obj.encrypt(base64_source_code_with_pad)
    print("[+] source code encrypt successfully :)")
    print("[+] converting encrypted source code to base64 ...")
    enc_base64_source_code = base64.b64encode(enc_source_code)
    print("[+] encrypted source code to base64 successfully :)")
    print("[+] generating some random characters ...")
    len_rnadom_chr = random.randrange(5,15)
    print("[+] random characters lenght is : " + str(len_rnadom_chr))
    return enc_base64_source_code.decode() + generate_random_string(len_rnadom_chr) , len_rnadom_chr , AES_key , AES_iv , len(pad)

print('''
   ____        _     _ _             _      __                     _             
  / __ \      | |   (_) |           | |    / _|                   | |            
 | |  | |_   _| |__  _| |_      ___ | |__ | |_ _   _ ___  ___ __ _| |_ ___  _ __ 
 | |  | | | | | '_ \| | __|    / _ \| '_ \|  _| | | / __|/ __/ _` | __/ _ \| '__|
 | |__| | |_| | |_) | | |_    | (_) | |_) | | | |_| \__ \ (_| (_| | || (_) | |   
  \___\_\\__,_|_.__/|_|\__|    \___/|_.__/|_|  \__,_|___/\___\__,_|\__\___/|_| 
  ___          ___ _      _                ___       _    _ _   
 | _ )_  _    / __(_)_ __| |_  ___ _ _    / _ \ _  _| |__(_) |_ 
 | _ \ || |  | (__| | '_ \ ' \/ -_) '_|  | (_) | || | '_ \ |  _|
 |___/\_, |   \___|_| .__/_||_\___|_|     \__\_\\_,_|_.__/_|\__|
      |__/          |_|  
      
Github : https://github.com/CipherQubit
================================================================================      
    ''')
parser=argparse.ArgumentParser()
parser.add_argument('<input file  >', nargs='*', default=[1, 2, 3], help='input file path for obfuscation')
parser.add_argument('<output file >', nargs='*', default=[1, 2, 3], help='output file path')
args=parser.parse_args()
    
if __name__ == "__main__":
    source_code_file = open(sys.argv[1],"r")
    obfusticated_source_code_file = open(sys.argv[2],"w")
    print("[+] reading source code : " + (sys.argv[1]))
    source_code = source_code_file.read()
    print("[+] source code read successfully :)")
    source_code_obf = obfuscate(source_code)
    enc_obj = convert_source_to_encrypted_source_code(source_code_obf)
    str1 = generate_random_string(random.randrange(1,10)) 
    str2 = generate_random_string(random.randrange(1,10))
    str3 = generate_random_string(random.randrange(1,10))
    str4 = generate_random_string(random.randrange(1,10))
    print("[+] generating loader ...")
    loader = str1 + "=" + str1 + "[:len(" + str1 + ")" + "-" + str(enc_obj[1]) + "]\n"
    loader += str1 + "=" + str1 +  ".encode()\n"
    loader += str1 + "=" +  "base64.b64decode(" + str1 + ")\n"
    loader += str2 + "=" + "'"+enc_obj[2].decode() + "'\n"
    loader += str2 + "=" + str2 + ".encode()\n"
    loader += str3 + "=" + "'"+enc_obj[3].decode() + "'\n"
    loader += str3 + "=" + str3 + ".encode()\n"
    loader += str4 + "=" + "AES.new(" + str2 + ",AES.MODE_CBC,"+ str3 + ")\n"
    loader += str3 + "=" + str4 + ".decrypt(" + str1 + ")\n"
    loader += str3 + "=" + str3 + ".decode()\n"
    loader += str3 + "=" + str3 + "[:len("  + str3 + ")-"+str(enc_obj[4])+ "]\n"
    loader += str3 + "=" + str3 + ".encode()\n"
    loader += str3 + "=" +  "base64.b64decode(" + str3 + ").decode()\n"
    print("[+] writing obfusticated source code to : " + sys.argv[2])
    print("[+] writing loader to : " + sys.argv[2])
    obfusticated_source_code_file.write("from Crypto.Cipher import AES\nimport base64\nimport sys\n")
    obfusticated_source_code_file.write("sys.setrecursionlimit(1000000000)\n")
    obfusticated_source_code_file.write(str1 + "='''" + enc_obj[0] + "'''\n")
    obfusticated_source_code_file.write(obfuscate(loader)+"\n")
    obfusticated_source_code_file.write(obfuscate("eval(compile("+ str3 +",'<string>','exec'))"))
    print("[+] done :)")