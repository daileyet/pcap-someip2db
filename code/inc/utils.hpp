#ifndef __UTILS_H__
#define __UTILS_H__
#include <ProtocolType.h>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <string>
#include <stdio.h>
#include <time.h>
#include <vector>
#include <regex>

namespace pcap_util {

template <typename T> std::string int_to_hex(T i, bool prefix = true) {
  std::stringstream stream;
  stream << "0x" << std::setfill('0') << std::setw(sizeof(T) * 2) << std::hex
         << (i & 0xFFFF);
  return stream.str();
}

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType);



// Get current date/time, format is YYYY-MM-DD.HH:mm:ss
const std::string currentDateTime() ;

void replaceAll(std::string &str, const std::string &from, const std::string &to);

std::vector<std::string> stringSplit(const std::string& str, char delim);

} // namespace pcap_util
#endif // __UTILS_H__