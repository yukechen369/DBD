#-*- encoding: utf-8 -*-
# !python2
# Parse New Pcap file
pcaplist = ['1.pcap','2.pcap','3.pcap','4.pcap','5.pcap','6.pcap','7.pcap','8.pcap','9.pcap','10.pcap',
'11.pcap','12.pcap','13.pcap','14.pcap','15.pcap','16.pcap','17.pcap','18.pcap','19.pcap','20.pcap',
'21.pcap','22.pcap','23.pcap','24.pcap','25.pcap','26.pcap','27.pcap','28.pcap','29.pcap','30.pcap',
'31.pcap','32.pcap','1.pcap','2.pcap','3.pcap','4.pcap','5.pcap','6.pcap','7.pcap','8.pcap','9.pcap','10.pcap',
'11.pcap','12.pcap','13.pcap','14.pcap','15.pcap','16.pcap','17.pcap','18.pcap','19.pcap','20.pcap',
'21.pcap','22.pcap','23.pcap','24.pcap','25.pcap','26.pcap','27.pcap','28.pcap','29.pcap','30.pcap',
'31.pcap','32.pcap','1.pcap','2.pcap','3.pcap','4.pcap','5.pcap','6.pcap','7.pcap','8.pcap','9.pcap','10.pcap',
'11.pcap','12.pcap','13.pcap','14.pcap','15.pcap','16.pcap','17.pcap','18.pcap','19.pcap','20.pcap',
'21.pcap','22.pcap','23.pcap','24.pcap','25.pcap','26.pcap','27.pcap','28.pcap','29.pcap','30.pcap',
'31.pcap','32.pcap','1.pcap','2.pcap','3.pcap','4.pcap']

# pcaplist = ['17.pcap','18.pcap','19.pcap','20.pcap','21.pcap','22.pcap' ]

import sys
reload(sys)
sys.setdefaultencoding('utf8')
#print(sys.getdefaultencoding())
from PcapParser import PcapParser

try:
    i = 1
    # for files in pcaplist:
    for t in range(1):
        filename = "../dns2tcp/" + 'dns2-2.pcap'
        # filename = "../test/" + files
        # filename = "../200/" + '200 (' + str(i) + ').pcap'
        i += 1
        try:

            #PcapParser( Max_packet_count, mode, filename, verbose):
            obj_dns_parser = PcapParser(10000000, 3, filename, 1)
            obj_dns_parser.start_parse()
            #break
        except Exception as e:
            print (e)
            continue

except Exception as e:
    print(e)
