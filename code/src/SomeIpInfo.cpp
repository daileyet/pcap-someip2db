#include "SomeIpInfo.hpp"

SomeIpStoreCfg SomeIpInfo::someipStoreCfg{};

SomeIpInfo::SomeIpInfo(pcpp::SomeIpLayer *layer, pcpp::RawPacket *rawPacket,
                       size_t no) {
  m_ipInfo.no = no;
  reslovePacketMetaInfo(*layer, *rawPacket, m_ipInfo);
  resolveSomeIpData(*layer);
}

void SomeIpInfo::printHelp() {
  std::cout << std::endl
            << "No:" << m_ipInfo.no << std::endl
            << "Timestamp:" << timespec_to_ms(m_ipInfo.timestamp) << std::endl
            << "IP id:" << pcap_util::int_to_hex<uint16_t>(m_ipInfo.ipId)
            << std::endl
            << "IP  protocol:"
            << pcap_util::int_to_hex<uint8_t>(m_ipInfo.protocol) << std::endl
            << "IP src:" << m_ipInfo.src.toString() << std::endl
            << "IP dest:" << m_ipInfo.dest.toString() << std::endl
            << "MessageID:" << pcap_util::int_to_hex<uint32_t>(m_message_id)
            << std::endl
            << "ServiceID: " << pcap_util::int_to_hex<uint16_t>(m_service_id)
            << std::endl
            << "MethodID: " << pcap_util::int_to_hex<uint16_t>(m_method_id)
            << std::endl
            << "Length: " << m_length_val << std::endl
            << "RequestID: " << m_request_id << std::endl
            << "SessionID: " << m_session_id << std::endl
            << "ClientID: " << m_client_id << std::endl
            << "ProtocolVersion: "
            << pcap_util::int_to_hex<uint8_t>(m_protocol_ver) << std::endl
            << "InterfaceVersion: "
            << pcap_util::int_to_hex<uint8_t>(m_interface_ver) << std::endl
            << "MessageType: " << pcap_util::int_to_hex<uint8_t>(m_message_type)
            << std::endl
            << "ReturnCode: " << pcap_util::int_to_hex<uint8_t>(m_return_code)
            << std::endl
            << "Payload size: " << m_payload_size << std::endl
            << m_payload_hex << std::endl;
}

void SomeIpInfo::resolveSomeIpData(pcpp::SomeIpLayer &layer) {
  m_message_id = layer.getMessageID();
  m_service_id = layer.getServiceID();
  m_method_id = layer.getMessageID();
  m_length_val = layer.getLengthField();
  m_request_id = layer.getRequestID();
  m_session_id = layer.getSessionID();
  m_client_id = layer.getClientID();
  m_protocol_ver = layer.getProtocolVersion();
  m_interface_ver = layer.getInterfaceVersion();
  m_message_type = layer.getMessageTypeAsInt();
  m_return_code = layer.getReturnCode();
  m_payload_size = layer.getPduPayloadSize();
  m_payload_hex = pcpp::byteArrayToHexString(layer.getPduPayload(),
                                             layer.getPduPayloadSize());
}
void SomeIpInfo::reslovePacketMetaInfo(pcpp::SomeIpLayer &layer,
                                       pcpp::RawPacket &packet,
                                       PacketMetaInfo &info) {
  m_ipInfo.timestamp = packet.getPacketTimeStamp();
  pcpp::Layer *tcpOrUDPLayer = layer.getPrevLayer();
  if (tcpOrUDPLayer) {
    pcpp::IPLayer *ipLayer =
        dynamic_cast<pcpp::IPLayer *>(tcpOrUDPLayer->getPrevLayer());
    if (ipLayer) {
      info.src = ipLayer->getSrcIPAddress();
      info.dest = ipLayer->getDstIPAddress();
      pcpp::IPv4Layer *ipv4Layer = dynamic_cast<pcpp::IPv4Layer *>(ipLayer);
      if (ipv4Layer) {
        pcpp::iphdr *ipHdr = ipv4Layer->getIPv4Header();
        info.ipId = pcpp::netToHost16(ipHdr->ipId);
        info.protocol = static_cast<pcpp::IPProtocolTypes>(ipHdr->protocol);
      } else {
        std::cerr << "Cannot determine IPv4Layer" << std::endl;
      }
    } else {
      std::cerr << "Cannot determine IPLayer" << std::endl;
    }
  }
}