
import socket
import dpkt

file = open("test1.pcap", mode='rb')
pcap = dpkt.pcap.Reader(file)
for item in pcap:
    try:
        eth = dpkt.ethernet.Ethernet(item[1])
        smac = eth.src
        dmac = eth.dst
        #print(smac, dmac)
        ip = eth.data
        #print(ip.src)
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        #print(ip.get_proto(ip.p).__name__)

        #print(src, dst)
        transf_data = ip.data
        spn = transf_data.sport
        ppn = transf_data.dport
        #print(spn, ppn)
    except:
        print(ip.src)
        print("这是ip")

'''
import dpkt
import socket
from dpkt.compat import compat_ord
def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

if __name__ == '__main__':
    list=[]
    file_path=r"D:\PyCharmProjects\Lab1\test0.pcap"
    file=open(file_path,mode='rb')
    reader=dpkt.pcap.Reader(file)
    for ts, pkt in reader.readpkts():
        e=0
        eth=dpkt.ethernet.Ethernet(pkt)
        smac = mac_addr(eth.src)
        dmac = mac_addr(eth.dst)
        ip=eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        protocol=ip.get_proto(ip.p).__name__
        trans_data=ip.data
        sport=trans_data.sport
        dport=trans_data.dport
        trans=[smac,dmac,src,dst,sport,dport,protocol,src+"  "+dst+"  "+str(sport)+"  "+str(dport)+"  "+protocol,pkt]
        if len(list)==0:
            flow=[]
            flow.append(trans)
            list.append(flow)
        else:
            for i in list:
                if(i[0][7]==trans[7]):
                    i.append(trans)
                    e=1
            if(e==0):
                flow = []
                flow.append(trans)
                list.append(flow)
    e=0
    print ("流的总数为",len(list))
    print("源IP            目的IP           源端口    目的端口    协议   源mac    目的mac")
    for i in list:
        print(i[0][7],"流的长度为",len(i),i[0][0],i[0][1])
        trans=i[0][0]+i[0][1]
        for j in i:
            trans2=j[0]+j[1]
            if(trans!=trans2):
                e=1
                print("存在ip地址对应多个mac地址")
    if(e==0):
        print("不存在ip地址对应多个mac地址")
    result=[]
    for i in list:
        trans=[]
        for j in i:
            trans.append(j[8])
        result.append(trans)
    print("流被放入了result列表中，result[0]到result[5]就是六个流的内容")

'''


