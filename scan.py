#!/usr/bin/env python2.7

from scapy.all import *
from ipaddress import *
import csv
import argparse

def create_ports_list(ports):
    # This function converts a string of comma seperated ports (including ranges) to a python list.
    
    # First, split the string list into a python list

    ports = ports.split(",")
    split_ports = []

    for i in ports:

        # For every element of the ports list, if it's a range (i.e. it contains a hyphen) convert this into a list.
        # For example, this will change "1-5" to "1,2,3,4,5" 

        if "-" in i:
            i = i.split("-")
            port_start = int(i[0])
            port_end = int(i[1])
            split_ports.extend([j for j in range(port_start, port_end+1)])
            
        # If it's not a range (i.e. a single port), append it to the new list

        else:
            split_ports.append(int(i))

    # Convert all elements to a string and sort the list

    ports = list(map(str, sorted(split_ports)))

    # Return the list of ports

    return ports

def arp_ping(ip, timeout):
    # Use ARP to discover live hosts on a local network, using Scapy.

    # Craft and send an ARP request to the broadcast address, asking for the MAC of the requested IP

    req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip))

    res, _ = srp(req, timeout=timeout, verbose = 0)

    live = False

    # If we recieve a response from ARP, we know the host is live

    if len(res) != 0:
        live = True

    # Return whether the host is live or not as a boolean value

    return live

def port_scan(ip, port, timeout):
    # Perform a SYN port scan, using Scapy.

    # Craft a IP datagram with a destination of the target IP
    # Then encapsulate this in a TCP segment with the SYN flag set and the required destination port

    ip_dgrm = IP(dst = str(ip))
    tcp_syn_packet = TCP(dport = int(port), flags = 'S')
    packet = ip_dgrm / tcp_syn_packet

    # Send the segment and wait for a response

    res = sr1(packet, timeout = timeout, verbose = 0)

    # Create a list to be used as output to the function

    out = [str(ip), str(port)]

    # If we get a response, categorise it!

    if res is not None:   
        if res.haslayer(TCP) and res[TCP].flags == 18:
            # If the response is TCP and contains the SYN / ACK flags (18 in Scapy) - the port is Open!
            out.extend(["Open", "SYN/ACK"])

        elif res.haslayer(TCP) and res[TCP].flags == 20:
            # If the response is TCP and contains the RST (/ACK) flag (20 in Scapy) - the port is Closed!
            out.extend(["Closed", "RST"])

        elif res.haslayer(ICMP) and res[ICMP].type == 3 and res[ICMP].code in [1, 2, 3, 9, 10, 13]:
            # If the response is ICMP, type 3 and code one of 1, 2, 3, 9, 10 or 13 - the port is Filtered!
            out.extend(["Filtered", "ICMP Response"])

    else:
        # If we get no response - the port is Filtered!
        out.extend(["Filtered", "No Response"])

    # Return the IP, Port and Status as a list

    return out

# --- Main Function ---

# Define our command line argument parser and assocaited option help messages.

parser = argparse.ArgumentParser(description="Perform a SYN port scan.")
parser.add_argument("network", type=str, help="Provide the target network using CIDR notation.")
parser.add_argument("-p", type=str, help="The ports required for the scan. Default is top 1000 TCP ports.")
parser.add_argument("-o", type=str, help="The name of the output file. Default file name is scan.csv.", default = "scan.csv")
parser.add_argument("-t", type=float, help="The timeout value in seconds. The default is 0.5 seconds", default = 0.5)

args = parser.parse_args()

# Assign user inputs to variables

network = args.network
output_file = args.o
ports = args.p
timing = args.t

# Assign / create a list of ports to scan, depending on user input

if ports is None:
    # If the user does not set the -p option, use top commonly open ports, as used by nmap
    # To find these, follow: https://securitytrails.com/blog/top-scanned-ports

    ports = """1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,
    306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,
    687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,
    1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,
    1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,
    1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,
    1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,
    2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,
    2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,
    3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,
    3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,
    4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,
    5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,
    5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,
    6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,
    7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,
    8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,
    9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,
    10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,
    14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,
    19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,
    32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,
    49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,
    61532,61900,62078,63331,64623,64680,65000,65129,65389"""

elif ports == "F":
    # If the user specifies '-p F', then top 100 commonly open ports are scanned, as used by nmap. 
    # This is the same as the '-F' option in nmap.
    # To find these, follow: https://securitytrails.com/blog/top-scanned-ports

    ports = """7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,
    1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,
    8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"""

elif ports == "-":
    # If the user specifies '-p-', then all 65535 ports are scanned. This is the same as the '-p-' option in nmap.

    ports = "1-65535"

# Now convert the string port list to a python list, using our function create_ports_list

ports = create_ports_list(ports)

print "\n- ARP Ping for Live Hosts."

# Convert our user defined netowrk from CIDR notation to a ipaddress.IPv4Network object
# This acts like a list of IPs to iterate over

network = IPv4Network(unicode(network,"utf-8"), False)

live_network = []

# Define variables to track percentage complete

count = 0
old_percent = 0
total_hosts = network.num_addresses

# For every host in the user defined network, send an ARP request using arp_ping function to determine if it is live
# Store the IP of live hosts in the live_network list

for ip in network:

    count += 1
    percent = int((float(count)/float(total_hosts))*100)

    if arp_ping(ip, timing):
        live_network.append(ip)
        
    if percent % 10 == 0 and percent != old_percent:
        old_percent = percent
        print "     " + str(percent) + "% complete."

# Overwrite network with network of live hosts

network = live_network

# If no hosts are found, terminate the script.

if not network:
    print "~ No live hosts found, aborting..."
    exit()

print "- SYN Scan for Open Ports."

# Define variables to track percetange complete

count = 0
total_ports = len(ports)
old_percent = 0

output = []

# For every port in list of user defined ports, perform a SYN port scan on every live host

for port in ports:

    count += 1
    percent = int((float(count)/float(total_ports))*100)

    for ip in network:
        output.append(port_scan(ip, port, timing))
        
    if percent % 10 == 0 and percent != old_percent:
        old_percent = percent
        print "     " + str(percent) + "% complete."

# Sort output by IP, as they are currently stored in ascending port order.

output = sorted(output, key = lambda host: map(int, host[0].split('.')))

print "- Writing to CSV."

# Create a new output file, with name scan.csv or a user defined name

with open(output_file, 'wb') as f:
    writer = csv.writer(f, delimiter=',')
    writer.writerow(["IP", "Port", "Status", "Reason"])
    writer.writerows(output)

print "~ Done! \n"