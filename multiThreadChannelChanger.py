from threading import Thread
import subprocess,shlex,time
import threading
locky = threading.Lock()

def Change_Freq_channel(channel_c):
    print('Channel:',str(channel_c))
    command = 'iwconfig wlan1mon channel '+str(channel_c)
    command = shlex.split(command)
    subprocess.Popen(command,shell=False) # To prevent shell injection attacks ! 

while True:


        t = Thread(target=Change_Freq_channel,args=(channel_c,))
        t.daemon = True
        locky.acquire()
        t.start()
        time.sleep(0.1)
        locky.release()