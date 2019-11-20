#include "extensions/access_loggers/grpc/config_utils.h"

#include "envoy/singleton/manager.h"

#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Extensions {
namespace AccessLoggers {
namespace GrpcCommon {

// Singleton registration via macro defined in envoy/singleton/manager.h
SINGLETON_MANAGER_REGISTRATION(grpc_access_logger_cache);

std::shared_ptr<GrpcCommon::GrpcAccessLoggerCache>
getGrpcAccessLoggerCacheSingleton(Server::Configuration::FactoryContext& context) {
  std::string overridden_downstream_ip;
  for (const auto& field : context.localInfo().node().metadata().fields()) {
    if (field.first == "OVERRIDDEN_DOWNSTREAM_IP" &&
        field.second.kind_case() == ProtobufWkt::Value::kStringValue) {
      overridden_downstream_ip = field.second.string_value();
      break;
    }
  }

  return context.singletonManager().getTyped<GrpcCommon::GrpcAccessLoggerCache>(
      SINGLETON_MANAGER_REGISTERED_NAME(grpc_access_logger_cache), [&context, overridden_downstream_ip] {
        return std::make_shared<GrpcCommon::GrpcAccessLoggerCacheImpl>(
            context.clusterManager().grpcAsyncClientManager(), context.scope(),
            context.threadLocal(), context.localInfo(), overridden_downstream_ip);
      });
}
} // namespace GrpcCommon
} // namespace AccessLoggers
} // namespace Extensions
} // namespace Envoy
