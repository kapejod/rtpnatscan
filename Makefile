CROSS_ARCH="Linux"
CROSS_COMPILE="$(TARGET_CROSS)"
CFLAGS=-O2 -Wall -g 

%.lo : %.c
	$(CC) $(CFLAGS) -o $@ -c $<

all:	rtpnatscan

rtpnatscan:	rtp_nat_scan.o
	$(CC) -o rtpnatscan $^

rtcpnatscan:	rtcp_nat_scan.o
	$(CC) -o rtcpnatscan $^

clean:
	rm -f *.o rtpnatscan rtcpnatscan
