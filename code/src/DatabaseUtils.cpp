#include "DatabaseUtils.hpp"

bool DatabaseUtils::storeSomeIpInfos(
    std::vector<std::shared_ptr<SomeIpInfo>> &infos) {
  try {
    SQLite::Database db(SomeIpInfo::someipStoreCfg.db_path,
                        SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
    if (SomeIpInfo::someipStoreCfg.keep_record == false) {
      db.exec(SQL_DROP_TABLE_SOMEIP_DATA);
      db.exec(SQL_CREATE_TABLE_SOMEIP_DATA);
    }
    db.exec(SQL_DROP_VIEW_SOMEIP_DATA);
    db.exec(SQL_CREATE_VIEW_SOMEIP_DATA);
    // Begin transaction
    SQLite::Transaction transaction(db);
    for (int i = 0; i < infos.size(); i++) {
      SQLite::Statement query(db, SQL_INSERT_TABLE_SOMEIP_DATA);
      std::shared_ptr<SomeIpInfo> info = infos[i];
      SQLite::bind(
          query, (int64_t)info->m_ipInfo.no,
          timespec_to_ms(info->m_ipInfo.timestamp),
          info->m_ipInfo.src.toString(), info->m_ipInfo.dest.toString(),
          info->m_ipInfo.ipId, info->m_ipInfo.protocol, info->m_service_id,
          info->m_method_id, info->m_length_val, info->m_session_id,
          info->m_client_id, info->m_protocol_ver, info->m_interface_ver,
          info->m_message_type, info->m_return_code,
          (int64_t)info->m_payload_size, info->m_payload_hex);
      query.exec();
    }
    // Commit transaction
    transaction.commit();
  } catch (std::exception &e) {
    std::cout << "exception: " << e.what() << std::endl;
    return false;
  }
  return true;
}