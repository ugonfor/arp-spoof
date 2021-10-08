LDLIBS=-lpcap -lpthread

all: arp-spoof

arp-spoof: main.o arp-spoof.o header/arphdr.o header/ethhdr.o header/ip.o header/mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o header/*.o