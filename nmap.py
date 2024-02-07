# install nmap to work 
import nmap
scanner = nmap.PortScanner()
print("Nmap Version: ", scanner.nmap_version())
ip_addr = input("Enter the IP Address to scan: ")
response = input("""\nPlease enter the type of scan you want to run
                1)TCP SYN ACK Scan
                2)UDP Scan
                3)Regular Scan
                4)OS Detection
                \n""")
print("You have selected option: ", response)

# If user's input is 1, perform a SYN/ACK scan
if response == '1':
    # Here, v is used for verbose, which means if selected it will give extra information
    # -sS means perform a TCP SYN connect scan, it send the SYN packets to the host
    # Well-known ports (0-1023)
    # Registered ports (1024-49151)
    # Ephemeral ports (49152-65535)
    scanner.scan(ip_addr,arguments='-v -sS')
    # state() tells if target is up or down
    print("Ip Status: ", scanner[ip_addr].state())
    # all_protocols() tells which protocols are enabled like TCP UDP etc
    print("protocols: ", scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())

# If user's input is 2, perform a UDP Scan
elif response == '2':
    # Here, v is used for verbose, which means if selected it will give #extra information
    # 0-1023 means the port number we want to search on
    # -sU means perform a UDP SYN connect scan, it send the SYN packets to #the host
    scanner.scan(ip_addr,arguments='-v -sU')
    # state() tells if target is up or down
    print("Ip Status: ", scanner[ip_addr].state())
    # all_protocols() tells which protocols are enabled like TCP UDP etc
    print("protocols: ", scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['udp'].keys())

# If user's input is 3, perform a Regular Scan
elif response == '3':
    # Works on default arguments
    scanner.scan(ip_addr)
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print("protocols: ",scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())

# If user's input is 4, perform a OS Detection Scan
elif response == '4':
    print(scanner.scan(ip_addr, arguments='-O')['scan'][ip_addr]['osmatch'][0]['name'])
else:
    print("Please choose a number from the options above")
