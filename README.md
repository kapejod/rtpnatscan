# rtpnatscan
A minimalistic command line tool to check if your RTP proxy / NAT helper is vulnerable to RTP NAT stealing attacks.

### Installation:
```
git clone git@github.com:kapejod/rtpnatscan.git
cd rtpnatscan
make
```

### Usage:
```
./rtpnatscan hostname port_range_start port_range_end [packets_per_port] [payload_size] [payload_type]
```
