#include "utils.hpp"

namespace pcap_util {
std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType) {
  switch (protocolType) {
  case pcpp::Ethernet:
    return "Ethernet";
  case pcpp::IPv4:
    return "IPv4";
  case pcpp::TCP:
    return "TCP";
  case pcpp::UDP:
    return "UDP";
  case pcpp::HTTPRequest:
  case pcpp::HTTPResponse:
    return "HTTP";
  case pcpp::SomeIP:
    return "SomeIP";
  case pcpp::GenericPayload:
    return "GenericPayload";
  default:
    return "Unknown";
  }
}

const std::string currentDateTime() {
  time_t now = time(0);
  struct tm tstruct;
  char buf[80];
  tstruct = *localtime(&now);
  // Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
  // for more information about date/time format
  strftime(buf, sizeof(buf), "%Y%m%d%X", &tstruct);

  return buf;
}

// a function that replaces all occurrences of from with to in str
void replaceAll(std::string &str, const std::string &from,
                const std::string &to) {
  size_t start_pos = 0; // start from the beginning
  while ((start_pos = str.find(from, start_pos)) !=
         std::string::npos) {                  // while there is a match
    str.replace(start_pos, from.length(), to); // replace it
    start_pos += to.length();                  // advance the position
  }
}

std::vector<std::string> stringSplit(const std::string &str, char delim) {
  std::string s;
  s.append(1, delim);
  std::regex reg(s);
  std::vector<std::string> elems(
      std::sregex_token_iterator(str.begin(), str.end(), reg, -1),
      std::sregex_token_iterator());
  return elems;
}

} // namespace pcap_util