# Test bed
#

# !python2

from DnsAnalyser import map_analyse_data
import socket

myhost = socket.gethostname()
#print(myhost)

filename = ''

if myhost=="DESKTOP-CLMMIFQ":
    path_prefix = "C:/Users/Manmeet Singh/Google Drive/PhD/"
else:
    path_prefix = "C:/Users/Manmeet Singh/Google Drive/PhD/"

while filename == "":
    try:
        filename = raw_input('Enter Complete Filename? :')
        # map_analyse_data("E:\PhD\python\scripts\sample\sample.pcap", 1)
        map_analyse_data(path_prefix +  filename, 2)
    except:
        print ("File Doesn't Exist")

