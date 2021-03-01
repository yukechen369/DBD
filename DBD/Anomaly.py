
import datetime, socket, sys, ipaddr, time, dpkt, thread, csv, struct, getopt, os

class Anomaly:

    def __init__(self, filename):
        self.infected = 0
        self.clean_hosts = 0
        self.filename = filename
        self.counter = 1
        tmp_out_file = filename.split('.')
        self.consolidate = 1
        self.add_header = 1
        if self.consolidate:
            self.outfile = open('output/DNS_FP_Anomaly.csv', 'a+')
        else:
            self.outfile = open(tmp_out_file[0] + '_anomaly.csv', 'w')

    def parse_file(self):
        req_infile = open(self.filename, 'r')
        req_reader = csv.reader(req_infile, delimiter=',')
        count = 1
        tmpstr = ''
        for res in req_reader:
            try:
                if count == 1:
                    tmpstr += 'UUID,'
                    for items in res:
                        tmpstr += items + ','

                    tmpstr += 'Result,ResCode'
                    if self.add_header == 1:
                        self.outfile.writelines(tmpstr + '\n')
                    count += 1
                    continue
                if count == 1500000:
                    break
                self.read_record(res)
                count += 1
            except:
                print 'Error reading CSV record ' + str(count), sys.exc_info()
                continue

        #print '\nNumber of infected Hosts = ' + str(self.infected)
        #print '\nNumber of Clean Hosts = ' + str(self.clean_hosts) + '\n'
        self.outfile.close()

    def set_bit(self, int_type, offset):
        mask = 1 << offset
        return int_type | mask

    def codetoanomaly(self, int_type):
        result = ''
        for i in range(0, 16, 1):
            mask = 1 << i
            if mask & int_type != 0:
                if result == '':
                    result = 'A' + str(i)
                else:
                    result += ',A' + str(i)

        if result == '':
            return '-'
        else:
            return result

    def read_record(self, res):
        try:
            tmp_result = 0
            tmp_str = ''
            if int(res[2]) < 100:
                return
            if int(res[2]) > 7500:
                tmp_result = self.set_bit(tmp_result, 0)
            if int(res[3]) > 1500:
                tmp_result = self.set_bit(tmp_result, 1)
            if int(res[4]) > 1000:
                tmp_result = self.set_bit(tmp_result, 2)
            if int(res[5]) > 300:
                tmp_result = self.set_bit(tmp_result, 3)
            if int(res[6]) > 500:
                tmp_result = self.set_bit(tmp_result, 4)
            if int(res[8]) > 10:
                tmp_result = self.set_bit(tmp_result, 5)
            if int(res[10]) > 500:
                tmp_result = self.set_bit(tmp_result, 6)
            if int(res[11]) > 25:
                tmp_result = self.set_bit(tmp_result, 7)
            if int(res[12]) > 500:
                tmp_result = self.set_bit(tmp_result, 8)
            if int(res[13]) > 5:
                tmp_result = self.set_bit(tmp_result, 14)
            if int(res[2]) > 500 and int(res[2]) / int(res[3]) < 1.5:
                tmp_result = self.set_bit(tmp_result, 9)
            if int(res[2]) > 500 and int(res[2]) / int(res[3]) > 20:
                tmp_result = self.set_bit(tmp_result, 9)
            if int(res[20]) > 12:
                tmp_result = self.set_bit(tmp_result, 10)
            if int(res[15]) > 70:
                tmp_result = self.set_bit(tmp_result, 11)
            if int(res[17]) > 30:
                tmp_result = self.set_bit(tmp_result, 12)
            if int(res[3]) > 1000 and int(res[23]) > 1000 and int(res[3]) / int(res[23]) > 10 or int(res[3]) > 1000 and int(res[23]) > 1000 and int(res[3]) / int(res[23]) < 1.1:
                tmp_result = self.set_bit(tmp_result, 13)
            tmp_str += str(self.counter) + ','
            for items in res:
                tmp_str += items + ','

            if tmp_result == 0:
                tmp_str += 'Clean,' + str(tmp_result)
                out_res = tmp_str.split(',')
                out_filtered = out_res[2].split('_')
                self.clean_hosts += 1
            else:
                tmp_str += 'Bot,' + str(tmp_result)
                out_res = tmp_str.split(',')
                out_filtered = out_res[2].split('_')
                self.infected += 1
            self.counter += 1
            self.outfile.writelines(tmp_str + '\n')
        except:
            print 'Error in read_record ', sys.exc_info()

if __name__ == '__main__':
    obj = Anomaly('output/DNS_FP_CSV.csv')
    obj.parse_file()
# okay decompiling Anomaly.pyc
