#!/bin/bash

#This script is created by:
#Name: Yap Ching Siong
#Student code: S14
#Class: CFC2407
#Lecturer: James

#This script is created to automate and perform the following actions:
#1. Discover live hosts on LAN network that the script is executed on.
#2. User able to input any IP to exclude from the enumeration and weak password check.
#3. The script will check whether the IP entered by user exists in the discovered LAN IP.
#4. Proceed to scan for open ports on found hosts using Nmap.
#5. User to choose username and password list for password checking OR generate a password list using cupp.
#6. The script will check whether the file exists before proceeding to next step.
#7. Check for weak passwords using hydra, on the first login service(ftp, ssh, telnet) found.
#8. All results will be saved into reports that can be later accessed by user.
#9. At the end of script a general statistics will be printed. User will be given a choice to view report on Text Editor.

#Basic actions are mention above each function.
#For detail explanation of the code, please refer to pdf file that is zipped together.

#NOTE: User inputs are required throughout the execution of script.

#References:
#https://www.cyberciti.biz/faq/linux-ip-command-examples-usage-syntax/
#https://linuxhint.com/echo-newline-bash/
#https://www.cyberciti.biz/faq/unix-linux-shell-script-sorting-ip-addresses/
#https://unix.stackexchange.com/questions/419424/sorting-multiple-columns-with-the-second-column-being-sorted-by-numerical-order
#https://stackoverflow.com/questions/5947742/how-to-change-the-output-color-of-echo-in-linux



#The installTools function will install Nmap, Hydra and Cupp tools.
function installTools()
{
echo "*************************************"
echo "Starting Tools Installation & Updates"
echo "*************************************"
sleep 2
sudo apt-get update -y
sudo apt-get install nmap -y
sudo apt-get install hydra -y
sudo apt-get install cupp -y
echo "*************************************"
echo "Tools Installation & Update Completed"
echo "*************************************"
echo -e "\n\n\n"
sleep 5
}


#The createDir function will check for 'Vulner' folder's existence in the system.
#If folder does not exist, it will create 'Vulner' folder to store results and reports.
function createDir()
{
wDir=$(pwd)
if [ ! -d "$wDir/Vulner" ]
then
	mkdir $wDir/Vulner
fi
}


#The networkScan function will check for network range of the LAN.
#Then use the result to scan for live hosts on the LAN.
function networkScan()
{
cd Vulner
echo "****************************"
echo "Checking Local Network Range"
echo "****************************"
echo
sleep 2
dateTime=$(date | awk '{print $NF,$2,$3,$4}')
start=$(date +%s)
fileID=$(echo $dateTime | tr -d [:space:] | tr -d [:punct:])
mkdir $wDir/Vulner/Result$fileID
cd Result$fileID
networkRange=$(ip address | grep inet | grep eth0 | awk '{print $2}')
echo "Your Local Area Network Range is" $networkRange
echo
echo "**********************************"
echo "Local Network Range Scan Completed"
echo "**********************************"
echo -e "\n\n\n"
sleep 5
echo "***************************"
echo "Scanning LAN For Live Hosts"
echo "***************************"
echo
sleep 2
nmap -sn $networkRange | grep report | awk '{print $NF}' | sort -t . -k1,1n -k2,2n -k3,3n -k4,4n >> LiveHost.lst
echo "List of Live Hosts Found: "
cat LiveHost.lst
echo
echo "****************************"
echo "Live Host Scanning Completed"
echo "****************************"
echo -e "\n\n\n"
sleep 5
}



#The confirmDevice function notifies user of the IP the script will exclude from enumeration.
#User is able to input any IP to exlude from enumeration.
#Then the script will check whether the IP input by user exists in the LAN before proceeding to enumeration step.
function confirmDevice()
{
hostIp=$(hostname -I | tr -d [:space:])
echo $hostIp > ExcludeIp.lst
dgIp=$(route -n | grep UG | awk '{print $2}' | uniq)
echo $dgIp >> ExcludeIp.lst
echo "******************************************"
echo "Preparing To Enumerate Selected Live Hosts"
echo "******************************************"
echo
echo -e "Default Gateway(${CYAN}$dgIp${NONE}) And Current Machine(${CYAN}$hostIp${NONE}) Will Be ${CYAN}Excluded${NONE} From Enumeration."
echo
echo -e "${CYAN}Enter IP Address${NONE}(eg.DHCP Server, Virtual Network Adapter)${CYAN} To Be Excluded${NONE} From Enumeration.
To Input ${CYAN}More Than 1 IP Address${NONE}, Please Input In This Format(${CYAN}192.168.23.1${NONE},${CYAN}192.168.23.2${NONE}): "
read excludeIp
echo $excludeIp | tr ',' '\n' >> ExcludeIp.lst
cat LiveHost.lst | grep -xv -f ExcludeIp.lst > sort.lst
while [ $(cat sort.lst | wc -l) != $(($(cat LiveHost.lst | wc -l)-$(cat ExcludeIp.lst | wc -l))) ]
do
	rm ExcludeIp.lst
	rm sort.lst
	echo
	echo -e "${RED}One Of The IP Entered Does not Belong To The List Of Live Hosts.${NONE} Please Re-Enter."
	echo -e "\n"
	sleep 2
	hostIp=$(hostname -I | tr -d [:space:])
	echo $hostIp > ExcludeIp.lst
	dgIp=$(route -n | grep UG | awk '{print $2}' | uniq)
	echo $dgIp >> ExcludeIp.lst
	echo -e "Default Gateway(${CYAN}$dgIp${NONE}) And Current Machine(${CYAN}$hostIp${NONE}) Will Be ${CYAN}Excluded${NONE} From Enumeration."
	echo
	echo -e "${CYAN}Enter IP Address${NONE}(eg.DHCP Server, Virtual Network Adapter)${CYAN} To Be Excluded${NONE} From Enumeration."
	echo -e "To Input ${CYAN}More Than 1 IP Address${NONE}, Please Input In This Format(${CYAN}192.168.23.1${NONE},${CYAN}192.168.23.2${NONE}): "
	read excludeIp
	echo $excludeIp | tr ',' '\n' >> ExcludeIp.lst
	cat LiveHost.lst | grep -xv -f ExcludeIp.lst > sort.lst
done
cat sort.lst | sort -t . -k1,1n -k2,2n -k3,3n -k4,4n > EnumerateIp.lst
echo
echo "List Of IP/s That Will Be Enumerated: "
cat EnumerateIp.lst
echo
}



#The enumDevice function uses namp to scan for open ports and possible vulnerabilities.
function enumDevice ()
{
echo "*****************************************"
echo "Enumerating Live Hosts, Please Be Patient"
echo "*****************************************"
echo
for x in $(cat EnumerateIp.lst)
do
	sudo nmap $x --script=vuln -sV -O -oN $x.nmap
	echo
	echo "___ _   _ ____ _____     _____ ____  _   _   _    _" >> Individual_Report_$x.txt
	echo "|_ _| \ | |  _ \_ _\ \   / /_ _|  _ \| | | | / \  | |" >> Individual_Report_$x.txt
	echo " | ||  \| | | | | | \ \ / / | || | | | | | |/ _ \ | |" >> Individual_Report_$x.txt
	echo " | || |\  | |_| | |  \ V /  | || |_| | |_| / ___ \| |" >> Individual_Report_$x.txt
	echo "|___|_| \_|____/___|  \_/  |___|____/ \___/_/   \_\_____|" >> Individual_Report_$x.txt
	echo >> Individual_Report_$x.txt
	echo " ____  _____ ____   ___  ____ _____" >> Individual_Report_$x.txt
	echo "|  _ \| ____|  _ \ / _ \|  _ \_   _|" >> Individual_Report_$x.txt
	echo "| |_) |  _| | |_) | | | | |_) || |" >> Individual_Report_$x.txt
	echo "|  _ <| |___|  __/| |_| |  _ < | |" >> Individual_Report_$x.txt
	echo "|_| \_\_____|_|    \___/|_| \_\|_|" >> Individual_Report_$x.txt
	echo -e "\n" >> Individual_Report_$x.txt
	echo -e "${BOLD}Program Started On:${NONE} $dateTime" >> Individual_Report_$x.txt
	echo -e "${BOLD}Device IP:${NONE} $x" >> Individual_Report_$x.txt
	echo -ne "${BOLD}MAC Address:${NONE}" >> Individual_Report_$x.txt
	cat $x.nmap | grep -i "mac address" | awk -Fs: '{print $2}' >> Individual_Report_$x.txt
	echo -ne "${BOLD}OS Details:${NONE}" >> Individual_Report_$x.txt
	cat $x.nmap | grep -i "os details" | awk -Fs: '{print $2}' >> Individual_Report_$x.txt
	echo -e "\n${BOLD}Nmap Enumeration & Vulnerabilities Scan Results:${NONE}" >> Individual_Report_$x.txt
	cat $x.nmap >> Individual_Report_$x.txt
done
echo "*********************"
echo "Enumeration Completed"
echo "*********************"
echo -e "\n\n\n"
sleep 5
}


#The defUserList function requests user to input path of user name list.
#The script will check whether the file exists in the system.
function defUserList()
{
echo "*************************************"
echo "Preparing To Check For Weak Passwords"
echo "*************************************"
echo
read -p "Please Enter File Path Of The User List: " userlistPath
echo
if [ ! -f "$userlistPath" ];
then
	echo -e "${RED}File Does Not Exist.${NONE} Please Re-Enter."
	echo
	defUserList
fi
}


#The defPassList requests user to input path of password list.
#Or generate a password list using cupp.
#The script will check whether the file exists in the system.
function defPassList()
{
read -p "Select One Of the Following Option For The Password List
1. Use Your Own Password List
2. Create A Password List Using cupp
Any Other Input will Require Re-Entry Of User List Path.
Enter Option: " passwdChoice
case $passwdChoice in
1)
echo
echo "You Have Chosen To Use Your Password List."
read -p "Please Specify The Path Of The Password List: " passwdlistPath
echo
if [ ! -f "$passwdlistPath" ]
then
	echo -e "${RED}File Does Not Exist.${NONE} Please Re-Enter."
	echo
	defPassList
fi
;;

2)
echo
echo "You Have Chosen To Create A Password List."
cupp -i
passwdlist=$(ls -lrt | tail -n 1 | awk '{print $NF}')
passwdlistPath=$(pwd)/$passwdlist
echo
;;

*)
echo
echo -e "${RED}Invalid Input,${NONE} Please Re-enter."
echo
defPassList
;;
esac
}


#The passwdCheck function uses hydra to perform a brute force on the list of hosts.
#It will return results of the brute force.
function passwdCheck()
{
echo "*******************************************"
echo "Brute Force In Progress. Please Be Patient."
echo "Results Will Be Printed.					 "
echo "*******************************************"
for x in $(cat EnumerateIp.lst)
do
	hydraIp=$(cat $x.nmap | grep 'scan report' | awk '{print  $NF}')
	hydraPort=$(cat $x.nmap | grep open | grep -E 'ftp|ssh|telnet' | head -n 1 | awk -F/ '{print $1}')
	hydraService=$(cat $x.nmap | grep open | grep -E 'ftp|ssh|telnet' | head -n 1 | awk '{print $3}')
	echo -e "\n\n${BOLD}Brute Force Results:${NONE} " >> Individual_Report_$x.txt
	hydra $hydraIp -s $hydraPort $hydraService -L $userlistPath -P $passwdlistPath -o hydra_$hydraIp.txt >> Individual_Report_$x.txt
	if [ $(cat hydra_$hydraIp.txt | grep login | wc -c) == 0 ]
	then
		echo >> Individual_Report_$x.txt
		echo -e "${GREEN}No Valid Passwords Found for $hydraIp${NONE}"
		echo -e "${GREEN}No Valid Passwords Found for $hydraIp${NONE}" >> Individual_Report_$x.txt
		echo -e "\n" >> Individual_Report_$x.txt
	else
		echo >> Individual_Report_$x.txt
		echo -e "${RED}Valid Passwords Found for $hydraIp${NONE}"
		echo -e "${RED}Valid Passwords Found for $hydraIp${NONE}" >> Individual_Report_$x.txt
		echo -e "\n" >> Individual_Report_$x.txt
	fi
done
end=$(date +%s)
echo
echo "************************"
echo "Password Check Completed"
echo "************************"
echo -e "\n\n\n"
sleep 5
}


#The statistics function will return date/time of script execution, duration of execution,
# Devices found, enumerated and excluded.
function statistics()
{
echo "******************"
echo "General Statistics"
echo "******************"
sleep 2
echo "Program Started on $dateTime."
duration=$((end-start))
echo "Time taken: $(($duration/3600)) hours $(($duration/60)) min $(($duration%60)) sec"
echo "Number Of Devices Found: $(cat LiveHost.lst | wc -l)"
echo "Number Of Devices Excluded From Enumeration: $(cat ExcludeIp.lst | wc -l)"
echo "Number Of Devices Enumerated: $(cat EnumerateIp.lst | wc -l)"
sleep 2
}


#The reportSum function compiles report for user.
function reportSum()
{
touch Report_Summary.txt
echo " ____  _____ ____   ___  ____ _____ " >> Report_Summary.txt
echo "|  _ \| ____|  _ \ / _ \|  _ \_   _|" >> Report_Summary.txt
echo "| |_) |  _| | |_) | | | | |_) || |" >> Report_Summary.txt
echo "|  _ <| |___|  __/| |_| |  _ < | |" >> Report_Summary.txt
echo "|_| \_\_____|_|    \___/|_| \_\|_|" >> Report_Summary.txt
echo >> Report_Summary.txt
echo " ____  _   _ __  __ __  __    _    ______   __">> Report_Summary.txt
echo "/ ___|| | | |  \/  |  \/  |  / \  |  _ \ \ / /" >> Report_Summary.txt
echo "\___ \| | | | |\/| | |\/| | / _ \ | |_) \ V / " >> Report_Summary.txt
echo " ___) | |_| | |  | | |  | |/ ___ \|  _ < | |  " >> Report_Summary.txt
echo "|____/ \___/|_|  |_|_|  |_/_/   \_\_| \_\|_|  " >> Report_Summary.txt
echo -e "\n" >> Report_Summary.txt
echo -e "${BOLD}Program Started On:${NONE} $dateTime" >> Report_Summary.txt
echo -e "\n${BOLD}LAN Network Range:${NONE} $networkRange" >> Report_Summary.txt
echo -e "\n${BOLD}Live Hosts Found On LAN:${NONE} " >> Report_Summary.txt
cat LiveHost.lst >> Report_Summary.txt
echo -e "\n${BOLD}IP/s Excluded From Enumeration:${NONE} " >> Report_Summary.txt
cat ExcludeIp.lst  >> Report_Summary.txt
echo -e "\n${BOLD}Enumerated IP/s:${NONE} " >> Report_Summary.txt
cat EnumerateIp.lst >> Report_Summary.txt
for x in $(cat EnumerateIp.lst)
do
	echo -e "\n" >> Report_Summary.txt
	echo -e "\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" >> Report_Summary.txt
	cat Individual_Report_$x.txt >> Report_Summary.txt
done
}


#The viewReport function allows user to view all reports, view individual device's report,
# or exit the program.
function viewReport()
{
echo -e "\nDetail Reports Are Located in ${CYAN}$(pwd)${NONE} directory.\n"
read -p "To View Report, Please Choose From The Following Options...
1. View Report Summary(Includes All Device's Reports).
2. View Report On Specific IP Address/Device.
Enter Any Other Input To Exit This Program.
Enter Option: " reportChoice
case $reportChoice in
1)
echo
echo "You Have Chosen To View Full Report."
cat Report_Summary.txt
viewReport;;

2)
echo
echo "You Have Chosen To View A Specific Report"
read -p "Please Enter An IP Address From The Following List Of Enumerated IP:
$(cat EnumerateIp.lst)

Enter An IP Address: " ipChoice
echo
while [ ! -f "Individual_Report_$ipChoice.txt" ];
do
	echo -e "${RED}File Does Not Exist.${NONE} Please Re-Enter IP Address."
	echo
	read -p "Please Enter An IP Address From The Following List Of Enumerated IP:
$(cat EnumerateIp.lst)

Enter An IP Address: " ipChoice
	echo
done
cat Individual_Report_$ipChoice.txt
viewReport
;;

*)
echo
echo "You Have Chosen to Exit. Bye!"
;;
esac
}


#Calls each function to execute,
# declare variables to use colors/bold fonts in the script.
# Finally, remove temp files created by this script.
installTools
createDir

NONE='\033[00m'
BOLD='\033[1m'
RED='\033[01;31m'
GREEN='\033[01;32m'
CYAN='\033[0;36m'

networkScan
confirmDevice
enumDevice
defUserList
defPassList
passwdCheck
statistics
reportSum
viewReport

for x in $(cat EnumerateIp.lst)
do
	sudo rm $x.nmap
	rm hydra_$x.txt
done

rm sort.lst
rm ExcludeIp.lst
rm LiveHost.lst
rm EnumerateIp.lst
