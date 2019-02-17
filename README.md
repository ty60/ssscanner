# Description
Ssscanner (Syn Scan Scanner) is a tool to detect SYN scans.
It will list suspicious SYN packets from the provided pcap file.

# Result
- Sample output
```
source ip:port, dest ip:port
192.168.0.2:5459, 192.168.0.1:23
192.168.0.3:53301, 192.168.0.1:1433
192.168.0.4:27747, 192.168.0.1:5555
192.168.0.5:56819, 192.168.0.1:22
...

```
![Scan Result](https://github.com/kttkyk/ssscanner/test.png)
- Can see that telnet (23), eternalblue (445), microsoft sql (1433) are being targeted.

# Method
Ssscanner looks for SYN port scanning packets by sliding a window from the past to the future.
When a SYN packet pops out from the tail of the window, ssscanner will check TCP packets within the window, which belong to the same conversation as the popping SYN packet.
- If there is a TCP packet which carries a payload, the SYN packet is considered normal SYN packet trying to establish a TCP connection.
- If there is NO TCP packet which carries a payload, the SYN packet is considered as a port scanning packet.

The method can detect both scans, with RST packet (e.g., default nmap), and without RST packet (e.g., mirai). However the performance and accuracy depend on the chosen window size.


# Usage
1. Install python3
2. `pip install -r requiements.txt`
3. `python ssscanner.py pcapfile.pcap`

```
usage: ssscanner.py [-h] [-w WINDOWSIZE] [-q] [--bar BAR] pcapfile

positional arguments:
  pcapfile

optional arguments:
  -h, --help            show this help message and exit
  -w WINDOWSIZE, --windowsize WINDOWSIZE
  -q, --quiet           No output description
  --bar BAR             Path to output bar chart
```


# Caution
- If it is slow minify pcap file before scanning, using tools such as tshark.
- Window size is important to the accuracy of the tool.
- Determine window size depending on how dense/sparse the traffic is in the pcap.
