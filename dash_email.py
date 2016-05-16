#!/usr/bin/python
import requests, socket, struct, binascii, time, json, urllib2
# github.com/smugzombie
# Original code found here: http://www.aaronbell.com/how-to-hack-amazons-wifi-button/

# If you know your dash, or have multiple dash buttons you can define them below, anything not defined below will be printed to the screen in real time to help your identify your dash button
macs = {'44650d0d479e':'dash'}

def sendMessage():
        url = "https://bouncerelay.com/api/1.0/sendmail.json"

        payload = "{\"apikey\":\"XXGETXXXYOURXXXOWNXXXAPIXXKEY\",\"message\":\"Someone Pushed The Button!\",\"to\":\"test@testertesttest.com\",\"subject\":\"Button Pushed\"}"
        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            }

        response = requests.request("POST", url, data=payload, headers=headers)

        print(response.text)

rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

while True:
    packet = rawSocket.recvfrom(2048)
    ethernet_header = packet[0][0:14]
    ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)
    # skip non-ARP packets
    ethertype = ethernet_detailed[2]
    if ethertype != '\x08\x06':
        continue
    # read out data
    arp_header = packet[0][14:42]
    arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
    source_mac = binascii.hexlify(arp_detailed[5])
    source_ip = socket.inet_ntoa(arp_detailed[6])
    dest_ip = socket.inet_ntoa(arp_detailed[8])
    if source_mac in macs:
        #print "ARP from " + macs[source_mac] + " with IP " + source_ip
        if macs[source_mac] == 'dash':
            sendMessage()
#    else:
#        print "Unknown MAC " + source_mac + " from IP " + source_ip
