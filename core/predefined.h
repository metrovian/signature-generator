#pragma once
// clang-format off
#define RETURN_CLEANUP(retcode, code)   do { retcode = code; goto cleanup; } while(0)
#define LOG_PATH                        std::string(__FILE__).substr(3)
#define LOG_EXIT()                      spdlog::trace("[exit] [{}:{}] {}", LOG_PATH, __LINE__, __func__)
#define LOG_ENTER()                     spdlog::debug("[enter] [{}:{}] {}", LOG_PATH, __LINE__, __func__)
#define LOG_VALUE(now)                  spdlog::info("[value] [{}:{}] {}", LOG_PATH, __LINE__, now)
#define LOG_PROGRESS(now, max)          spdlog::info("[render] [{}:{}] {}/{}", LOG_PATH, __LINE__, now, max)
#define LOG_WARN(condition)             spdlog::warn("[warn] [{}:{}] {}", LOG_PATH, __LINE__, std::string(#condition))
#define LOG_CONDITION(condition)        spdlog::error("[condition] [{}:{}] {}", LOG_PATH, __LINE__, std::string(#condition))
#define LOG_ARGUMENT(condition)         spdlog::critical("[argument] [{}:{}] {}", LOG_PATH, __LINE__, std::string(#condition))

#define RSA_TRIAL_ITERATION             1000000
#define RSA_FERMAT_ITERATION            1000000
#define RSA_POLLARDS_RHO_ITERATION      1000000
#define RSA_POLLARDS_P1_ITERATION       100000
#define RSA_WILLIAMS_P1_ITERATION       100000
#define ECDSA_TRIAL_ITERATION           1000000
#define ECDSA_SHANKS_ITERATION          1000000
// clang-format on
