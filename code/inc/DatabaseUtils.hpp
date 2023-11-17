#ifndef __DATABASEUTILS_H__
#define __DATABASEUTILS_H__

#include "SomeIpInfo.hpp"
#include <SQLiteCpp/SQLiteCpp.h>
#include <SQLiteCpp/VariadicBind.h>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#define DB_DEF_NAME_PREFIX "pcap_someip_"
#define SQL_DROP_TABLE_SOMEIP_DATA "DROP TABLE IF EXISTS someip_data"
#define SQL_DROP_VIEW_SOMEIP_DATA "DROP VIEW IF EXISTS someip_data_vw"

#define SQL_CREATE_TABLE_SOMEIP_DATA                                           \
  "CREATE TABLE someip_data (\
no INTEGER PRIMARY KEY, \
ts INTEGER,\
ip_src TEXT,\
ip_dest TEXT,\
ip_id INTEGER,\
ip_protocol INTEGER,\
service_id INTEGER,\
method_id INTEGER,\
length INTEGER,\
session_id INTEGER,\
client_id INTEGER,\
protocol_ver INTEGER,\
interface_ver INTEGER,\
message_type INTEGER,\
return_code INTEGER,\
payload_size INTEGER,\
payload_hex TEXT)"

#define SQL_INSERT_TABLE_SOMEIP_DATA                                           \
  "INSERT INTO someip_data values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"

#define SQL_CREATE_VIEW_SOMEIP_DATA "CREATE VIEW someip_data_vw as SELECT *,\
format('0x%04X',service_id) as service_id_hex, \
format('0x%04X',method_id) as method_id_hex,\
iif(service_id==0xffff,1,0) as is_sd,\
iif(ip_protocol==17,1,0) as is_udp \
FROM someip_data;"

class DatabaseUtils {
public:
  static bool storeSomeIpInfos(std::vector<std::shared_ptr<SomeIpInfo>> &infos);
};
#endif // __DATABASEUTILS_H__