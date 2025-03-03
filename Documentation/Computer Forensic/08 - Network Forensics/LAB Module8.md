
# Identifying and Investigating an FTP Brute Force Attack using Splunk






# Preguntas del Lab

## 1.
### On CHFIV10 WINDOWS SERVER 2016 machine, upload FTP Brute Force.csv evidence file located in the directory, C:\CHFI-Tools\Evidence Files\Wireshark Sample Capture Files\Files for Network Forensics on Splunk. After uploading the evidence file, you will observe packets with several entries. Examine the entries and specify the host name in the answer field.
WIN-SU2M9G4F4S5

## 2.
### On CHFIV10 WINDOWS SERVER 2016 machine, upload FTP Brute-force log file that is located at C:\CHFI-Tools\Evidence Files\Wireshark Sample Capture Files\Files for Network Forensics in the Kiwi Log Viewer tool and locate the log no.349. Response: ____________ is the text that you observe under the ‘info’ section of the specified log entry.
530 User cannot log in


## 3.
### Open DNS Remote Shell.pcap file located at C:\CHFI-Tools\Evidence Files\Wireshark Sample Capture Files\Files for Network Forensics using Wireshark on your CHFIV10 WINDOWS SERVER 2016 machine. Filter the traffic flowing to and from port 53 by using the command tcp.port == 53 in the Filter field. After applying the filter, you will see that in packet number 28, the source IP (192.168.1.2) is trying to establish connection with destination IP (192.168.1.3). Mention in the below answer field the flag that you see in the packet.
PSH, ACK


