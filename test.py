import pyshark

cap = pyshark.FileCapture('./A-message-ethernet.pcap')

count = 0

for pkt in cap:
    if (pkt.highest_layer == "QUIC"):
        count+=1
