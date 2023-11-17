#include "DatabaseUtils.hpp"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "SomeIpInfo.hpp"
#include "stdlib.h"
#include "utils.hpp"
#include <SomeIpLayer.h>
#include <iostream>
#include <set>
#include <vector>

struct AnalysisResult {
  uint32_t someip_size = 0;
  uint32_t someip_sd_size = 0;
  uint32_t someip_udp_size = 0;
  uint32_t someip_tcp_size = 0;
  std::string someip_services = "";
};

bool printUsage();
std::string getDbDefaultName();
bool processArgs(int argc, char *argv[]);
void analysisParsedResult(std::vector<std::shared_ptr<SomeIpInfo>> &someIpInfos,
                          AnalysisResult &result);

int main(int argc, char *argv[]) {

  if (processArgs(argc, argv) == false) {
    exit(1);
    return 1;
  }

  // use the IFileReaderDevice interface to automatically identify file type
  // (pcap/pcap-ng)
  // and create an interface instance that both readers implement
  pcpp::IFileReaderDevice *reader =
      pcpp::IFileReaderDevice::getReader(SomeIpInfo::someipStoreCfg.pcap_path);

  // verify that a reader interface was indeed created
  if (reader == NULL) {
    std::cerr << "Cannot determine reader for file type" << std::endl;
    return 1;
  }

  // open the reader for reading
  if (!reader->open()) {
    std::cerr << "Cannot open " << SomeIpInfo::someipStoreCfg.pcap_path
              << " for reading" << std::endl;
    return 1;
  }

  for (int i = 0; i < SomeIpInfo::someipStoreCfg.someip_ports.size(); i++) {
    pcpp::SomeIpLayer::addSomeIpPort(
        SomeIpInfo::someipStoreCfg.someip_ports[i]);
  }

  std::vector<std::shared_ptr<SomeIpInfo>> someIpInfos;
  pcpp::RawPacketVector rawPackets;
  reader->getNextPackets(rawPackets);
  std::cout << std::endl
            << "Total Packet size:" << rawPackets.size() << std::endl;

  for (size_t i = 0; i < rawPackets.size(); i++) {
    pcpp::RawPacket *rawPacket = rawPackets.at(i);
    pcpp::Packet parsedPacket(rawPacket);
    pcpp::SomeIpLayer *someipLayer =
        parsedPacket.getLayerOfType<pcpp::SomeIpLayer>(pcpp::SomeIP);
    if (someipLayer == NULL) {
      continue;
    }
    someIpInfos.push_back(std::make_shared<SomeIpInfo>(
        someipLayer, rawPacket, i + 1 + SomeIpInfo::someipStoreCfg.begin_no));
  }
  // close the file reader, we don't need it anymore
  reader->close();
  if (DatabaseUtils::storeSomeIpInfos(someIpInfos)) {
    AnalysisResult rs;
    analysisParsedResult(someIpInfos, rs);
    std::cout << std::endl
              << "Summary:" << std::endl
              << "SOME/IP packet size:" << rs.someip_size << std::endl
              << "SOME/IP SD packet size:" << rs.someip_sd_size << std::endl
              << "SOME/IP UDP packet size:" << rs.someip_udp_size << std::endl
              << "SOME/IP TCP packet size:" << rs.someip_tcp_size << std::endl
              << "SOME/IP avaiable services:" << rs.someip_services << std::endl
              << std::endl;
  } else {
    std::cout << std::endl
              << "Unable to store record into database." << std::endl;
  }
}

bool printUsage() {
  std::cout
      << std::endl
      << "Usage:\n"
      << "         --pcap <pcap file path> --ports <someip ports> [--db "
         "<extract data to stored database path>] [--keep] [--no <begin "
         "index>]\n"
      << "1. pcap file path ;example: --pcap /path/capture.pcap\n"
      << "2. someip used ports, split by comma; example: --ports 30501,30500\n"
      << "3. optional; database store path, default pcap_someip.db3 ;example: "
         "--db /path/someip_db.db3\n"
      << "4. optional; keep orginal record in database if already exits "
         "table.\n"
      << "5. optional; the recored no column begin index, default 0.\n"
      << "\nExample:\n"
      << " ./pcap-someip2db --pcap /home/sample.pcap --ports 30490,30500,30501 "
         "\n"
      << " ./pcap-someip2db --pcap /home/sample.pcap --ports 30490,30500,30501 "
         "--db "
         "/home/output.db3\n"
      << " ./pcap-someip2db --pcap /home/sample.pcap --ports 30490,30500,30501 "
         "--db "
         "/home/output.db3 --keep --no 12000\n"
      << std::endl;

  return false;
}

std::string getDbDefaultName() {
  std::string curr_time = pcap_util::currentDateTime();
  pcap_util::replaceAll(curr_time, ":", "");
  return DB_DEF_NAME_PREFIX + curr_time + ".db3";
}

bool processArgs(int argc, char *argv[]) {
  const char *pcap_path = 0;
  const char *someip_ports = 0;
  const char *db_path = 0;
  bool keep_record = false;
  const char *begin_no = 0;
  std::string pcap_path_prefix("--pcap");
  std::string db_path_prefix("--db");
  std::string someip_ports_prefix("--ports");
  std::string keep_record_prefix("--keep");
  std::string begin_no_prefix("--no");
  int32_t i = 1;
  if (argc < 5) {
    return printUsage();
  }
  while (i < argc) {
    if ((pcap_path_prefix == argv[i]) && (i + 1 < argc)) {
      i++;
      pcap_path = argv[i];
    }
    if ((someip_ports_prefix == argv[i]) && (i + 1 < argc)) {
      i++;
      someip_ports = argv[i];
    }
    if ((db_path_prefix == argv[i]) && (i + 1 < argc)) {
      i++;
      db_path = argv[i];
    }
    if ((keep_record_prefix == argv[i])) {
      keep_record = true;
    }
    if ((begin_no_prefix == argv[i]) && (i + 1 < argc)) {
      i++;
      begin_no = argv[i];
    }
    i++;
  }
  SomeIpInfo::someipStoreCfg.pcap_path = pcap_path;
  std::vector<std::string> someipPorts =
      pcap_util::stringSplit(someip_ports, ',');
  if (someipPorts.empty()) {
    return printUsage();
  }
  for (int i = 0; i < someipPorts.size(); i++) {
    SomeIpInfo::someipStoreCfg.someip_ports.push_back(
        atoi(someipPorts[i].c_str()));
  }
  if (db_path == nullptr) {
    SomeIpInfo::someipStoreCfg.db_path = getDbDefaultName();
  } else {
    SomeIpInfo::someipStoreCfg.db_path = db_path;
  }
  SomeIpInfo::someipStoreCfg.keep_record = keep_record;
  if (begin_no != nullptr) {
    SomeIpInfo::someipStoreCfg.begin_no = atol(begin_no);
  }

  return true;
}

void analysisParsedResult(std::vector<std::shared_ptr<SomeIpInfo>> &someIpInfos,
                          AnalysisResult &result) {
  std::set<uint16_t> services;
  for (int i = 0; i < someIpInfos.size(); i++) {
    SomeIpInfo &info = *someIpInfos[i].get();
    if (info.isTCP())
      result.someip_tcp_size++;
    if (info.isUDP())
      result.someip_udp_size++;
    if (info.isSD()) {
      result.someip_sd_size++;
    } else {
      result.someip_size++;
      services.insert(info.getServiceId());
    }
  }
  for (std::set<uint16_t>::iterator iter = services.begin();
       iter != services.end(); ++iter) {
    result.someip_services.append(pcap_util::int_to_hex<uint16_t>(*iter))
        .append(",");
  }
}