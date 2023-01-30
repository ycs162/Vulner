# Vulner
This script is created to automate and perform the following actions:
1. Discover live hosts on LAN network that the script is executed on.
2. User able to input any IP to exclude from the enumeration and weak password check.
3. The script will check whether the IP entered by user exists in the discovered LAN IP.
4. Proceed to scan for open ports on found hosts using Nmap.
5. User to choose username and password list for password checking OR generate a password list using cupp.
6. The script will check whether the file exists before proceeding to next step.
7. Check for weak passwords using hydra, on the first login service(ftp, ssh, telnet) found.
8. All results will be saved into reports that can be later accessed by user.
9. At the end of script a general statistics will be printed. User will be given a choice to view report on Text Editor.
