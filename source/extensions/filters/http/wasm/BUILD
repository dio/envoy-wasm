licenses(["notice"])  # Apache 2

# Public docs: docs/root/configuration/http_filters/wasm_filter.rst

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "wasm_filter_lib",
    srcs = ["wasm_filter.cc"],
    hdrs = ["wasm_filter.h"],
    deps = [
        "//include/envoy/http:codes_interface",
        "//include/envoy/server:filter_config_interface",
        "//include/envoy/upstream:cluster_manager_interface",
        "//source/extensions/common/wasm:wasm_lib",
        "//source/extensions/filters/http:well_known_names",
        "@envoy_api//envoy/config/filter/http/wasm/v3alpha:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":wasm_filter_lib",
        "//include/envoy/registry",
        "//source/common/common:empty_string",
        "//source/common/config:datasource_lib",
        "//source/extensions/common/wasm:wasm_lib",
        "//source/extensions/filters/http:well_known_names",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/config/filter/http/wasm/v3alpha:pkg_cc_proto",
    ],
)
