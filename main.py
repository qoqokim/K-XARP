import pcap
import dpkt
import os  # system() : 외부 프로그램을 호출하기 위함
import sys
import tkinter as tk # tkinter를 tk로 부르겠다.


Request_List = []
ARP_Table={}

def Right_Reply(sIP,sMAC): # ARP 테이블에 IP가 존재하는지 체크하는 함수
    if sIP in ARP_Table :  # ip가 ARP_table에 있는지 확인한다. 
        Mac_Check(sIP,sMAC)     
    else :
        ARP_Table[sIP] = sMAC
        #print(ARP_Table)


def Mac_Check(sIP,sMAC):   # Mac 주소가 중보되었는지 체크하는 함수
    if ARP_Table.get(sIP) == sMAC :
        print(" ******* 정상적인 응답(Reply) 패킷입니다. *******")
    else :
        print("\n#######################################")
        print("#                                                              #")
        print("#                                                              #")
        print("#             !!!! ARP Spoofing Attack !!!!              #")    
        print("#                                                              #")
        print("#      Attacker MAC is [",sMAC,"]!      #")
        print("#                                                              #")
        print("#                                                              #")
        print("#######################################")    
        print("#                                                              #")
        print("#          ARP Table 정적으로 설정 [시작]            #")
        print("#                                                              #")
        print("#######################################\n\n") 
        Right_Mac = ARP_Table.get(sIP)
        Static_Setting(sIP,Right_Mac)
        # ARP reply 패킷을 다시 보내서 다른 맥주소가 오는지 확인 해볼
        # static으로 설정하는 부분이 있어야함.


def Static_Setting(sIP,Right_Mac):   
    output = os.popen('netsh interface ip add neighbors "wlan0" ' + sIP + " " + Right_Mac)
    print(output.read())
    print("######  ARP Table 정적으로 설정  [완료]  ######\n")
    output = os.popen('arp -a')
    print(output.read())



def main():
    print("* ARP Table *")
    dev = pcap.findalldevs()[2]
    output = os.popen('arp -d')
    output = os.popen('arp -a')
    print(output.read())
    #request 패킷을 보낸 후 ARP 테이블을 생성한 뒤에 공격하고 탐지가 된다.

    i=1

    for timestamp, buf in pcap.pcap(name=dev):
        
        eth = dpkt.ethernet.Ethernet(buf)
        arp = eth.data

        if eth.type == 0x0806:  
           print("\n* [",i,"ARP ] *")

           if arp.op == 1 :  # request packet
               print(" - 요청(Request) 패킷 ------------------------------")
               print('|                                                             |')
               print('| 보내는 MAC (Sender.MAC) : ', ":".join(['%02x' % arp.sha[0],'%02x' % arp.sha[1],'%02x' % arp.sha[2],'%02x' % arp.sha[3],'%02x' % arp.sha[4],'%02x' % arp.sha[5]]),"|") # mac
               print('| 보내는 IP  (Sender.IP)        : ', str(int(arp.spa[0]))+"."+str(int(arp.spa[1]))+"."+str(int(arp.spa[2]))+"."+str(int(arp.spa[3])))  # ip
               print('|                                                             |')
               print('| 받는 MAC (Target.MAC)     : ', ":".join(['%02x' % arp.tha[0],'%02x' % arp.tha[1],'%02x' % arp.tha[2],'%02x' % arp.tha[3],'%02x' % arp.tha[4],'%02x' % arp.tha[5]]),"|") # mac
               print('| 받는 IP (Target.IP)             : ', str(int(arp.tpa[0]))+"."+str(int(arp.tpa[1]))+"."+str(int(arp.tpa[2]))+"."+str(int(arp.tpa[3])))  # ip
               print('|                                                             |')
               print(" ------------------------------------------------------")
               i+=1
               
               tIP = str(int(arp.tpa[0]))+"."+str(int(arp.tpa[1]))+"."+str(int(arp.tpa[2]))+"."+str(int(arp.tpa[3]))
               #print(tIP)

               if tIP in Request_List :
                   print("") # 이미 존재하는 Request IP
               else :
                   Request_List.append(tIP)                  
               #print(Request_List)
              

           if arp.op == 2 :  # reply packet
               print(" - 응답(Reply) 패킷  --------------------------------")
               print('|                                                             |')
               print('| 보내는 MAC (Sender.MAC) : ', ":".join(['%02x' % arp.sha[0],'%02x' % arp.sha[1],'%02x' % arp.sha[2],'%02x' % arp.sha[3],'%02x' % arp.sha[4],'%02x' % arp.sha[5]]),"|") # mac
               print('| 보내는 IP  (Sender.IP)        : ', str(int(arp.spa[0]))+"."+str(int(arp.spa[1]))+"."+str(int(arp.spa[2]))+"."+str(int(arp.spa[3])))  # ip
               print('|                                                             |')
               print('| 받는 MAC (Target.MAC)     : ', ":".join(['%02x' % arp.tha[0],'%02x' % arp.tha[1],'%02x' % arp.tha[2],'%02x' % arp.tha[3],'%02x' % arp.tha[4],'%02x' % arp.tha[5]]),"|") # mac
               print('| 받는 IP (Target.IP)             : ', str(int(arp.tpa[0]))+"."+str(int(arp.tpa[1]))+"."+str(int(arp.tpa[2]))+"."+str(int(arp.tpa[3])))  # ip
               print('|                                                             |')
               print(" ------------------------------------------------------")
               i+=1

               sIP = str(int(arp.spa[0]))+"."+str(int(arp.spa[1]))+"."+str(int(arp.spa[2]))+"."+str(int(arp.spa[3]))
               sMAC = "-".join(['%02x' % arp.sha[0],'%02x' % arp.sha[1],'%02x' % arp.sha[2],'%02x' % arp.sha[3],'%02x' % arp.sha[4],'%02x' % arp.sha[5]])
               #print(sIP,sMAC)
               
               if sIP in Request_List :# request 리스트 안에 있는 지 sIP 조회 하는 문구
                   Right_Reply(sIP,sMAC) # 올바른 reply패킷이므로 ARP_Table에 조회하는 함수로 넘어간다.
                   
               else :
                   print("\n!!!! request 리스트엔 없는 reply패킷 !!! ARP 스푸핑이 의심 됩니다 !!!!\n")
                   if sIP in ARP_Table :  # ARP_Table 에 Reply sender IP가 있는지 체크한다.
                       Mac_Check(sIP,sMAC)  # Mac 주소가 중복 되었는지 체크한다.
                       
                      
                   
if __name__=='__main__' :
    main()

    






