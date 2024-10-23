# pcap-analyzer
Analyze pcap packets from a file and count top source/destination IPs

By default `--mode destination`
```
# ./analyzer.py --help
usage: analyzer.py [-h] [--num_hosts NUM_HOSTS] [--mode {destination,source,both}] pcap_file

Analyze a pcap file and find the top IPs by packet count.

positional arguments:
  pcap_file             Path to the .pcap file to analyze

options:
  -h, --help            show this help message and exit
  --num_hosts NUM_HOSTS
                        Number of top IPs to display (default: 10)
  --mode {destination,source,both}
                        Which IPs to analyze: 'destination' (default), 'source', or 'both'
```
Example of usage top 5 sources:
```
# ./analyzer.py --num_hosts 5 --mode source file_from_tcpdump.pcap
Top 5 source IPs with the most packets:

IP Address        Packet Count
--------------  --------------
192.0.2.27                1999
192.0.2.23                 829
192.0.2.22                 369
192.0.2.12                 307
192.0.2.63                 274
```
