CROSS_ARCH="Linux"
CROSS_COMPILE="$(TARGET_CROSS)"
CFLAGS=-O2 -Wall -g 
OBJECTS=tools.o

%.lo : %.c
	$(CC) $(CFLAGS) -o $@ -c $<

all:	rtpnatscan

rtpnatscan:	rtp_nat_scan.o
	$(CC) -o rtpnatscan $^

clean:
	rm -f *.o rtpnatscan
