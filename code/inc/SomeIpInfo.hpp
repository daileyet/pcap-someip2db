#ifndef __SOMEIPINFO_H__
#define __SOMEIPINFO_H__

#include "timespec.h"
#include "utils.hpp"
#include <GeneralUtils.h>
#include <IPLayer.h>
#include <IPv4Layer.h>
#include <IpAddress.h>
#include <RawPacket.h>
#include <SomeIpLayer.h>
#include <SystemUtils.h>
#include <iostream>

struct SomeIpStoreCfg {
  std::string pcap_path;
  std::vector<uint16_t> someip_ports = {};
  std::string db_path;
  bool keep_record = false;
  size_t begin_no = 0;
};

class SomeIpInfo {
public:
  const uint16_t HEADER_LEN = 16;
  const uint16_t HEADER_MSGID_BEGIN = 0;
  const uint16_t HEADER_MSGID_LEN = 4;

  const uint16_t HEADER_LENGTH_BEGIN = 4;
  const uint16_t HEADER_LENGTH_LEN = 4;

  const uint16_t HEADER_REQUESTID_BEGIN = 8;
  const uint16_t HEADER_REQUESTID_LEN = 4;

  const uint16_t HEADER_PROTOCOLVER_BEGIN = 12;
  const uint16_t HEADER_PROTOCOLVER_LEN = 1;

  const uint16_t HEADER_INTERFACEVER_BEGIN = 13;
  const uint16_t HEADER_INTERFACEVER_LEN = 1;

  const uint16_t HEADER_MSGTYPE_BEGIN = 14;
  const uint16_t HEADER_MSGTYPE_LEN = 1;

  const uint16_t HEADER_RETURNCODE_BEGIN = 15;
  const uint16_t HEADER_RETURNCODE_LEN = 1;

  const uint32_t SD_MSGID = 0xffff8100;

  static SomeIpStoreCfg someipStoreCfg;
  struct PacketMetaInfo {
    size_t no;
    timespec timestamp;
    pcpp::IPAddress src;
    pcpp::IPAddress dest;
    uint16_t ipId = 0xFFFF;
    pcpp::IPProtocolTypes protocol =
        pcpp::IPProtocolTypes::PACKETPP_IPPROTO_UDP;
  };
  SomeIpInfo(pcpp::SomeIpLayer *layer, pcpp::RawPacket *rawPacket,
             size_t no = 0);
  SomeIpInfo(const SomeIpInfo &copy) = delete;
  SomeIpInfo &operator=(const SomeIpInfo &assign) = delete;
  ~SomeIpInfo() {}

  inline bool isUDP() {
    return m_ipInfo.protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_UDP;
  }

  inline bool isTCP() {
    return m_ipInfo.protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP;
  }

  inline bool isSD() { return m_message_id == SD_MSGID; }

  void printHelp();

  inline uint16_t getServiceId() { return m_service_id; }

  inline uint16_t getMethodId() { return m_method_id; }

private:
  void resolveSomeIpData(pcpp::SomeIpLayer &layer);
  void reslovePacketMetaInfo(pcpp::SomeIpLayer &layer, pcpp::RawPacket &packet,
                             PacketMetaInfo &info);

private:
  PacketMetaInfo m_ipInfo;
  uint32_t m_message_id;
  uint16_t m_service_id;
  uint16_t m_method_id;
  uint32_t m_length_val;
  uint32_t m_request_id;
  uint16_t m_session_id;
  uint16_t m_client_id;
  uint8_t m_protocol_ver;
  uint8_t m_interface_ver;
  uint8_t m_message_type;
  uint8_t m_return_code;
  size_t m_payload_size;
  std::string m_payload_hex;
  friend class DatabaseUtils;
};

#endif // __SOMEIPINFO_H__