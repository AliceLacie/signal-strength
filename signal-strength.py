import struct
import socket 
import os
import argparse
from argparse import RawTextHelpFormatter

parser = argparse.ArgumentParser(description='signal strength scan\n\nusage: python3 signal-strength.py -i <interface> -m <mac>',formatter_class=RawTextHelpFormatter)
parser.add_argument('-i', help='<interface>', required=True)
parser.add_argument('-m', help='<mac>',required=True)
args = parser.parse_args()

iface = args.i
scan_mac = args.m.upper()

def format_mac(bytes_addr):
    bytes_s = map('{:02x}'.format, bytes_addr) 
    return ":".join(bytes_s).upper()


rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
rawSocket.bind((iface, 0x0003))

while True:
    for channel in range(1, 14):
        os.system("iwconfig " + iface + " channel " + str(channel))
        
        frame = rawSocket.recvfrom(65536)[0]
        formats = 'BBH8sBBHHhhh'
        size = struct.calcsize(formats)
        header_version, header_padding, header_size, present_flag, flag, \
            speed, channel_frequencies, channel_flag, antenna_siggnel1, RX_flag, antenna_siggnel2 = struct.unpack(formats, frame[:size])

        check_beacon = 'ss'
        check_size = struct.calcsize(check_beacon)
        subtype, Version_type = struct.unpack(check_beacon, frame[size:size+check_size])
        subtype = int.from_bytes(subtype, "little")>>4
        
        if antenna_siggnel1<127:
            antenna = antenna_siggnel1
        else:
            antenna = antenna_siggnel1-255
        aformats = '2s6s6s6s2s8s2s2sBB'
        asize = struct.calcsize(aformats)
        if len(frame[size+check_size:]) < (size+check_size+asize)-(size+check_size):
            continue
        
        duration, receiver_address, transmitter_address, BSSID, idk,\
            timestamp,beacon_interval, capabilities_information,\
            tag_num, tag_len = struct.unpack(aformats, frame[size+check_size:size+check_size+asize])
        
        if scan_mac.upper() == format_mac(BSSID):
            print(f'[{scan_mac}] {antenna}dBM')