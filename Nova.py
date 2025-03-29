import scapy.all as scapy
import socket

def banner():
    print(r"""
                                               
                      :                        
  L.                 t#,                       
  EW:        ,ft    ;##W.                      
  E##;       t#E   :#L:WE                    ..
  E###t      t#E  .KG  ,#D  t      .DD.     ;W,
  E#fE#f     t#E  EE    ;#f EK:   ,WK.     j##,
  E#t D#G    t#E f#.     t#iE#t  i#D      G###,
  E#t  f#E.  t#E :#G     GK E#t j#f     :E####,
  E#t   t#K: t#E  ;#L   LW. E#tL#i     ;W#DG##,
  E#t    ;#W,t#E   t#f f#:  E#WW,     j###DW##,
  E#t     :K#D#E    f#D#;   E#K:     G##i,,G##,
  E#t      .E##E     G#t    ED.    :K#K:   L##,
  ..         G#E      t     t     ;##D.    L##,
              fE                  ,,,      .,, 
               ,                               
    """)
    print("[*] Welcome to the rizzy nova")
    print("[*] Type help to see cmds innit\n")

def scan():
    print("[*] scanning the huzz for devices")

 
    arp_request_broadcast = scapy.ARP(pdst="174.01010101/24")  # put your local network range
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") 
    arp_request_broadcast = broadcast/arp_request_broadcast

  
    result = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

    devices = []
    for sent, received in result:
      
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            hostname = "Unknown"

        devices.append({"ip": received.psrc, "mac": received.hwsrc, "hostname": hostname})

  
    print("\n[+] routerssssssingsss found on the net bruv:")
    print("IP Address\t\tMAC Address\t\tHostname")
    print("-----------------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}\t\t{device['hostname']}")

def command_handler():
    while True:
        command = input("$sudo >>> ")
        
        if command == "help":
            print("[*] the commands: 'scan', 'exit'")
        elif command == "scan":
            scan()
        elif command == "exit":
            print("[*] Exiting...")
            break
        else:
            print("[*] Unknown commanddddd Type help' for cmds rel")

def main():
    banner()
    command_handler()

if __name__ == "__main__":
    main()
