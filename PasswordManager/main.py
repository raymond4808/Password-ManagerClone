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
    with open ('password.txt', 'a') as f: #open file and append with auto close
        f.write(website + '|' + name + '|' + fer.encrypt(pwd.encode()).decode() +'\n') #encrypt converts str password into bytes then into storable encrypt str form

def edit():
    """ #testing password data backup
Google|tester|gAAAAABmVhlLefiVqpbdaxgPUr6GD61TwDtcpfFvOLmdnYUCnTGN8pHALftoxEG9XAVbF-SBVWWYvxEE_nYIQxrklwuqTjcACA==
Googler1|tester|gAAAAABmVhlataRYJYHP1iBrjufv36q4umfsoilp0F8T4DgSwsWhdV5z5biMRn5-lq_LmfH5d2BCQoYaQJcqyNxlDvWbIc5hwQ==
    """
    changed = False
    tempList=[]

    if os.path.getsize("password.txt") == 0:  # checks if the file is empty, if not proceeds forward
        print("No passwords saved")
        return

    existingInfo=""
    if os.path.exists('password.txt'):
        with open('password.txt', 'r+') as f:
            existingInfo= f.read()
    #print(existingInfo)

    with open ('password.txt', 'r+') as f: #open file and read with auto close
        for line in f:
            line.rstrip()
            holder = line.split('|')
            site = holder[0]
            user = holder[1]
            password=holder[2]
            decrypPwd=fer.decrypt(password.encode()).decode()
            tempList.append([site,user,decrypPwd])

        #sets pointer back to zero and clears the data
        f.seek(0)
        f.truncate()
        #print(tempList) #TS
        print("Please Confirm The Following Values for Editing:")
        website = input("Site Name: ").capitalize()
        username = input("User Name: ")
        pwd = input("Password: ")

        for i in tempList:
            if i[0] == website and i[1]==username and i[2] == pwd:
                changed = True
                print("Values confirmed! Please enter the following edited variables")
                newWebsite = input("Edited Site Name: ").capitalize()
                newUsername = input("Edited User Name: ")
                newPwd = input("New Edited Password:")
                while True:
                    if validPassCheck(newPwd):
                        break
                    else:
                        print("Invalid Password Requirement, Please Try Again")
                        print(
                            "Passwords must have a minimum requirement of: 6 characters long, contain 1 upper and lower case letter, one special character, and 1 numerical digit.")
                        newPwd = input("Edited Password: ")
                i[0] = newWebsite
                i[1] = newUsername
                i[2] = newPwd
                break

            else:
                continue
        if changed == False:
            print("The entered values do not match what we have on record try again")
        else:
            print("Exiting password editor")

        with open ('password.txt', 'a') as f:
            for i in tempList:
                currSite= i[0]
                currName = i[1]
                currPass= i[2]
                f.write(currSite + '|' + currName + '|' + fer.encrypt(currPass.encode()).decode() +'\n')

def validPassCheck(pwd): #checks regular expression requirement to validate pass
    regReq="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,25}$"
    regPattern= re.compile(regReq)
    checkPass= re.search(regPattern, pwd)

    if checkPass:
        print("Valid Password! Adding/Updating to password manager...")
        return True
    else:
        return False
def passManagerStart():
    while True:
        mode= input("Enter 'view' to access existing passwords | 'add' to add a new password | 'edit' to edit existing data | 'q' to exit out of the program \n")
        if mode == 'q':
            break

        if mode == "view" or mode == "v" or mode == "V":
            view()

        elif mode == "add" or mode == "a" or mode == "A":
            add()
        elif mode == "edit" or mode == "e" or mode == "E":
            edit()
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

