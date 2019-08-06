from scapy.all import *
import requests
import json
import time

hueData = {
    "ip":"192.168.1.4",
    "userId":"FnnXGbJozv4kg-7-zTt9KxHeClUoWQtACMyjARpp"
    }

lastUpdateTime=0


def arp_display(pkt):
    global lastUpdateTime
    if pkt[ARP].op == 1: #who-has (request)
        if pkt[ARP].hwsrc == '74:75:48:a7:c9:c4': # ARP Probe
            print("ARP Probe from:{}, op={},psrc={}".format(pkt[ARP].hwsrc,pkt[ARP].op,pkt[ARP].psrc))
            currentTime = time.time()
            if currentTime-lastUpdateTime<10:
                print("Recently updated!!")
                return
            else:
                lastUpdateTime=currentTime

            toggleHueLight(2,75)

def toggleHueLight(id,brightness):
    url = "http://{}/api/{}/lights/{}/state".format(hueData['ip'],hueData['userId'],id)
    state = getHueLightState(id)

    if state is True:
        data = {"on":False}
    else:
        data = {"on":True,"bri":int(254*brightness/100)}
        
    
    response = requests.put(url,data=json.dumps(data)).json()
    print(response)

def getHueLightState(id):
    url = "http://{}/api/{}/lights/{}".format(hueData['ip'],hueData['userId'],id)
    data = requests.get(url).json()
    #print(data['state']['on'])
    return data['state']['on']

print(sniff(prn=arp_display,filter="arp",store=0))
#toggleHueLight(2,50)
