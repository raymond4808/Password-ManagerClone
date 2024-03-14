import base64
import os
import hashlib
import re

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#testing push commit
def write_key(masterPass): #creates key from first time master password
    masterPass=b'masterPass'
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(masterPass))
    with open ('key.key', 'wb') as key_file:
        key_file.write(key)

def hashPassword(pwd): #creates hashed version of passed in str password
    return hashlib.sha3_256(pwd.encode()).hexdigest()

def writeHashMasterPass(masterPass): #used in first time initializing by creating and adding hashed master password to txt file
    hashedMasterPass = hashPassword(masterPass)
    with open ('master_pass.txt','w') as f:
        f.write(hashedMasterPass)

def load_key(): #reads and loads key into Fernet password encryption
    file= open ('key.key', 'rb')
    key=file.read()
    file.close()
    return key

def view(): #prints decrypted string of the site, username, password off of stored txt file
    with open ('password.txt', 'r') as f: #open file and read with auto close
        for line in f:
            line.rstrip()
            holder = line.split('|')
            site = holder[0]
            user= holder[1]
            password=holder[2]
            print("Site: " + site + "\nUsername: " + user + "\nPassword: " + fer.decrypt(password.encode()).decode() +"\n") #decrypt converts encrypted str to bytes then back to original readable str form

def add(): #adds website, username, password to text file and encrypts the password
    website= input('Site name: ').capitalize()
    name=input('Login Name: ')
    print ("Passwords must have a minimum requirement of: 6 characters long, contain 1 upper and lower case letter, one special character, and 1 numerical digit")
    pwd= input("Password: ")
    while True:
        if validPassCheck(pwd):
            break
        else:
            print("Invalid Password Requirement, Please Try Again")
            print("Passwords must have a minimum requirement of: 6 characters long, contain 1 upper and lower case letter, one special character, and 1 numerical digit.")
            pwd = input("Password: ")

    #left off here (working password validator)

    with open ('password.txt', 'a') as f: #open file and append with auto close
        f.write(website + '|' + name + '|' + fer.encrypt(pwd.encode()).decode() +'\n') #encrypt converts str password into bytes then into storable encrypt str form

def validPassCheck(pwd):
    regReq="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,25}$"
    regPattern= re.compile(regReq)
    checkPass= re.search(regPattern, pwd)

    if checkPass:
        print("Valid Password! Adding to password manager...")
        return True
    else:
        return False
def passManagerStart():
    while True:
        mode= input("Enter 'view' to access existing passwords | 'add' to add a new password | 'q' to exit out of the program \n")
        if mode == 'q':
            break

        if mode == "view":
            view()

        elif mode == "add":
            add()
        else:
            print("Enter invalid mode... please try again")

#start up
if os.path.getsize('key.key') <= 0: #generates key and master password upon first intializing program
    print("First time setup detected...")
    masterPwd = input("Enter permanent master password to access password manager... \n")
    write_key(masterPwd)
    key = load_key()
    fer = Fernet(key)
    writeHashMasterPass(masterPwd)
    print('Saved Master Password... Reinitializing program')

with open ('master_pass.txt', 'r') as f: #pulls up the proper hashed saved password
    storedMasterPass=f.read().strip()

masterPwd = input("Enter master password to access password manager... \n") #prompts user to keep entering master password until correct of 'q' for quitting program

while True:
    if masterPwd =='q':
        break

    if storedMasterPass != hashPassword(masterPwd):
        masterPwd = input("Enter the correct master password to access password manager or 'q' to quit... \n")

    else:
        key = load_key()
        fer = Fernet(key)
        break

if __name__ == '__main__':
    print('Password manager initializing')
    passManagerStart()
    print('Password manager closing')

