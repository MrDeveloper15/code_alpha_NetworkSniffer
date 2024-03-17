import socket
import struct
from ctypes import *

class IPHeader(Structure):

    _fields_ = [
        ("ihl",         c_ubyte, 4),
        ("version",     c_ubyte, 4),
        ("tos",         c_ubyte),
        ("len",         c_ushort),
        ("id",          c_ushort),
        ("offset",      c_ushort),
        ("ttl",         c_ubyte),
        ("protocol_num",c_ubyte),
        ("checksum",    c_ushort),
        ("src",         c_uint32),
        ("dst",         c_uint32),
    ]

    def __new__(self, data=None):
        return self.from_buffer_copy(data)

    def __init__(self, data=None):
        self.source_ip = socket.inet_ntoa(struct.pack("@I", self.src))
        self.destination_ip = socket.inet_ntoa(struct.pack("@I", self.dst))
        self.protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocols[self.protocol_num]
        except KeyError:
            self.protocol = str(self.protocol_num)

class TCPHeader(Structure):

    _fields_ = [
        ("source_port", c_ushort),
        ("dest_port",   c_ushort),
        ("sequence",    c_uint32),
        ("acknowledgment", c_uint32),
        ("offset_res",  c_ubyte, 4),
        ("tcp_flags",   c_ubyte, 4),
        ("window",      c_ushort),
        ("checksum",    c_ushort),
        ("urgent_ptr",  c_ushort),
    ]

    def __new__(self, data=None):
        return self.from_buffer_copy(data)

    def __init__(self, data=None):
        self.source_port = socket.ntohs(self.source_port)
        self.dest_port = socket.ntohs(self.dest_port)

def conn():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.bind(("0.0.0.0", 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return sock

def main():
    sniffer = conn()
    print('''                                                                                                                                                                       
         ,--.                                                                                                                                                          
       ,--.'|                ___                                               ,-.            .--.--.                                                                  
   ,--,:  : |              ,--.'|_                                         ,--/ /|           /  /    '.                 ,--,      .--.,    .--.,                       
,`--.'`|  ' :              |  | :,'           .---.    ,---.     __  ,-. ,--. :/ |          |  :  /`. /        ,---,  ,--.'|    ,--.'  \ ,--.'  \              __  ,-. 
|   :  :  | |              :  : ' :          /. ./|   '   ,'\  ,' ,'/ /| :  : ' /           ;  |  |--`     ,-+-. /  | |  |,     |  | /\/ |  | /\/            ,' ,'/ /| 
:   |   \ | :    ,---.   .;__,'  /        .-'-. ' |  /   /   | '  | |' | |  '  /            |  :  ;_      ,--.'|'   | `--'_     :  : :   :  : :      ,---.   '  | |' | 
|   : '  '; |   /     \  |  |   |        /___/ \: | .   ; ,. : |  |   ,' '  |  :             \  \    `.  |   |  ,"' | ,' ,'|    :  | |-, :  | |-,   /     \  |  |   ,' 
'   ' ;.    ;  /    /  | :__,'| :     .-'.. '   ' . '   | |: : '  :  /   |  |   \             `----.   \ |   | /  | | '  | |    |  : :/| |  : :/|  /    /  | '  :  /   
|   | | \   | .    ' / |   '  : |__  /___/ \:     ' '   | .; : |  | '    '  : |. \            __ \  \  | |   | |  | | |  | :    |  |  .' |  |  .' .    ' / | |  | '    
'   : |  ; .' '   ;   /|   |  | '.'| .   \  ' .\    |   :    | ;  : |    |  | ' \ \          /  /`--'  / |   | |  |/  '  : |__  '  : '   '  : '   '   ;   /| ;  : |    
|   | '`--'   '   |  / |   ;  :    ;  \   \   ' \ |  \   \  /  |  , ;    '  : |--'          '--'.     /  |   | |--'   |  | '.'| |  | |   |  | |   '   |  / | |  , ;    
'   : |       |   :    |   |  ,   /    \   \  |--"    `----'    ---'     ;  |,'               `--'---'   |   |/       ;  :    ; |  : \   |  : \   |   :    |  ---'     
;   |.'        \   \  /     ---`-'      \   \ |                          '--'                            '---'        |  ,   /  |  |,'   |  |,'    \   \  /            
'---'           `----'                   '---"                                                                         ---`-'   `--'     `--'       `----'             
                                                                                                                                                                       \nSniffer Started ...''')
    while True:
        try:
            raw_pack = sniffer.recvfrom(65535)[0]
            ip_header = IPHeader(raw_pack[0:20])
            if ip_header.protocol == "TCP":
                tcp_header = TCPHeader(raw_pack[20:40])
                print("Protocol: " + ip_header.protocol +
                      " Source: " + ip_header.source_ip +
                      " Source Port: " + str(tcp_header.source_port) +
                      " Destination: " + ip_header.destination_ip +
                      " Destination Port: " + str(tcp_header.dest_port))

        except KeyboardInterrupt:
            print("Exiting.........")
            exit(0)

if __name__ == "__main__":
    main()
