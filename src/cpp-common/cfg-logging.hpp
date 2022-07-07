/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Philippe Proulx <eeppeliteloop@gmail.com>
 */

#ifndef BABELTRACE_CPP_COMMON_CFG_LOGGING_HPP
#define BABELTRACE_CPP_COMMON_CFG_LOGGING_HPP

#ifndef BT_LOG_TAG
#    error Please define a logging tag with `BT_LOG_TAG` before including this file.
#endif

#include <babeltrace2/babeltrace.h>
#include "logging/log.h"

#define _BT_CLOG_OBJ_FMT_PREFIX "[%s] "

/*
 * Logs with the level `_lvl` using the configuration `_log_cfg`.
 */
#define BT_CLOG_EX(_lvl, _log_cfg, _fmt, ...)                                                      \
    if (BT_LOG_ON(_lvl)) {                                                                         \
        if ((_log_cfg).selfComp()) {                                                               \
            _bt_log_write((_lvl), BT_LOG_TAG, _BT_CLOG_OBJ_FMT_PREFIX _fmt,                        \
                          (_log_cfg).selfCompName(), ##__VA_ARGS__);                               \
        } else if ((_log_cfg).selfCompCls()) {                                                     \
            _bt_log_write((_lvl), BT_LOG_TAG, _BT_CLOG_OBJ_FMT_PREFIX _fmt,                        \
                          (_log_cfg).selfCompClsName(), ##__VA_ARGS__);                            \
        } else {                                                                                   \
            _bt_log_write((_lvl), BT_LOG_TAG, _fmt, ##__VA_ARGS__);                                \
        }                                                                                          \
    }

#define BT_CLOGF_EX(_log_cfg, _fmt, ...) BT_CLOG_EX(BT_LOG_FATAL, (_log_cfg), _fmt, ##__VA_ARGS__)
#define BT_CLOGE_EX(_log_cfg, _fmt, ...) BT_CLOG_EX(BT_LOG_ERROR, (_log_cfg), _fmt, ##__VA_ARGS__)
#define BT_CLOGW_EX(_log_cfg, _fmt, ...) BT_CLOG_EX(BT_LOG_WARNING, (_log_cfg), _fmt, ##__VA_ARGS__)
#define BT_CLOGI_EX(_log_cfg, _fmt, ...) BT_CLOG_EX(BT_LOG_INFO, (_log_cfg), _fmt, ##__VA_ARGS__)
#define BT_CLOGD_EX(_log_cfg, _fmt, ...) BT_CLOG_EX(BT_LOG_DEBUG, (_log_cfg), _fmt, ##__VA_ARGS__)
#define BT_CLOGT_EX(_log_cfg, _fmt, ...) BT_CLOG_EX(BT_LOG_TRACE, (_log_cfg), _fmt, ##__VA_ARGS__)
#define BT_CLOG(_lvl, _fmt, ...)         BT_CLOG_EX((_lvl), (BT_CLOG_CFG), _fmt, ##__VA_ARGS__)
#define BT_CLOGF(_fmt, ...)              BT_CLOG(BT_LOG_FATAL, _fmt, ##__VA_ARGS__)
#define BT_CLOGE(_fmt, ...)              BT_CLOG(BT_LOG_ERROR, _fmt, ##__VA_ARGS__)
#define BT_CLOGW(_fmt, ...)              BT_CLOG(BT_LOG_WARNING, _fmt, ##__VA_ARGS__)
#define BT_CLOGI(_fmt, ...)              BT_CLOG(BT_LOG_INFO, _fmt, ##__VA_ARGS__)
#define BT_CLOGD(_fmt, ...)              BT_CLOG(BT_LOG_DEBUG, _fmt, ##__VA_ARGS__)
#define BT_CLOGT(_fmt, ...)              BT_CLOG(BT_LOG_TRACE, _fmt, ##__VA_ARGS__)

/*
 * Logs with the level `_lvl` using the configuration `_log_cfg`.
 */
#define BT_CLOG_STR_EX(_lvl, _log_cfg, _str) BT_CLOG_EX((_lvl), (_log_cfg), "%s", _str)

#define BT_CLOGF_STR_EX(_log_cfg, _str) BT_CLOG_STR_EX(BT_LOG_FATAL, (_log_cfg), _str)
#define BT_CLOGE_STR_EX(_log_cfg, _str) BT_CLOG_STR_EX(BT_LOG_ERROR, (_log_cfg), _str)
#define BT_CLOGW_STR_EX(_log_cfg, _str) BT_CLOG_STR_EX(BT_LOG_WARNING, (_log_cfg), _str)
#define BT_CLOGI_STR_EX(_log_cfg, _str) BT_CLOG_STR_EX(BT_LOG_INFO, (_log_cfg), _str)
#define BT_CLOGD_STR_EX(_log_cfg, _str) BT_CLOG_STR_EX(BT_LOG_DEBUG, (_log_cfg), _str)
#define BT_CLOGT_STR_EX(_log_cfg, _str) BT_CLOG_STR_EX(BT_LOG_TRACE, (_log_cfg), _str)
#define BT_CLOG_STR(_lvl, _str)         BT_CLOG_STR_EX((_lvl), (BT_CLOG_CFG), _str)
#define BT_CLOGF_STR(_str)              BT_CLOG_STR(BT_LOG_FATAL, _str)
#define BT_CLOGE_STR(_str)              BT_CLOG_STR(BT_LOG_ERROR, _str)
#define BT_CLOGW_STR(_str)              BT_CLOG_STR(BT_LOG_WARNING, _str)
#define BT_CLOGI_STR(_str)              BT_CLOG_STR(BT_LOG_INFO, _str)
#define BT_CLOGD_STR(_str)              BT_CLOG_STR(BT_LOG_DEBUG, _str)
#define BT_CLOGT_STR(_str)              BT_CLOG_STR(BT_LOG_TRACE, _str)

/*
 * Logs an errno message with the level `_lvl`, using the configuration
 * `_log_cfg`, and having the initial message `_init_msg`.
 */
#define BT_CLOG_ERRNO_EX(_lvl, _log_cfg, _init_msg, _fmt, ...)                                     \
    if (BT_LOG_ON(_lvl)) {                                                                         \
        const auto errStr = g_strerror(errno);                                                     \
        if ((_log_cfg).selfComp()) {                                                               \
            _bt_log_write((_lvl), BT_LOG_TAG, _BT_CLOG_OBJ_FMT_PREFIX "%s: %s" _fmt,               \
                          (_log_cfg).selfCompName(), _init_msg, errStr, ##__VA_ARGS__);            \
        } else if ((_log_cfg).selfCompCls()) {                                                     \
            _bt_log_write((_lvl), BT_LOG_TAG, _BT_CLOG_OBJ_FMT_PREFIX "%s: %s" _fmt,               \
                          (_log_cfg).selfCompClsName(), _init_msg, errStr, ##__VA_ARGS__);         \
        } else {                                                                                   \
            _bt_log_write((_lvl), BT_LOG_TAG, "%s: %s" _fmt, _init_msg, errStr, ##__VA_ARGS__);    \
        }                                                                                          \
    }

#define BT_CLOGF_ERRNO_EX(_log_cfg, _init_msg, _fmt, ...)                                          \
    BT_CLOG_ERRNO_EX(BT_LOG_FATAL, (_log_cfg), _init_msg, _fmt, ##__VA_ARGS__)
#define BT_CLOGE_ERRNO_EX(_log_cfg, _init_msg, _fmt, ...)                                          \
    BT_CLOG_ERRNO_EX(BT_LOG_ERROR, (_log_cfg), _init_msg, _fmt, ##__VA_ARGS__)
#define BT_CLOGW_ERRNO_EX(_log_cfg, _init_msg, _fmt, ...)                                          \
    BT_CLOG_ERRNO_EX(BT_LOG_WARNING, (_log_cfg), _init_msg, _fmt, ##__VA_ARGS__)
#define BT_CLOGI_ERRNO_EX(_log_cfg, _init_msg, _fmt, ...)                                          \
    BT_CLOG_ERRNO_EX(BT_LOG_INFO, (_log_cfg), _init_msg, _fmt, ##__VA_ARGS__)
#define BT_CLOGD_ERRNO_EX(_log_cfg, _init_msg, _fmt, ...)                                          \
    BT_CLOG_ERRNO_EX(BT_LOG_DEBUG, (_log_cfg), _init_msg, _fmt, ##__VA_ARGS__)
#define BT_CLOGT_ERRNO_EX(_log_cfg, _init_msg, _fmt, ...)                                          \
    BT_CLOG_ERRNO_EX(BT_LOG_TRACE, (_log_cfg), _init_msg, _fmt, ##__VA_ARGS__)
#define BT_CLOG_ERRNO(_lvl, _init_msg, _fmt, ...)                                                  \
    BT_CLOG_ERRNO_EX((_lvl), (BT_CLOG_CFG), _init_msg, _fmt, ##__VA_ARGS__)
#define BT_CLOGF_ERRNO(_init_msg, _fmt, ...)                                                       \
    BT_CLOG_ERRNO(BT_LOG_FATAL, _init_msg, _fmt, ##__VA_ARGS__)
#define BT_CLOGE_ERRNO(_init_msg, _fmt, ...)                                                       \
    BT_CLOG_ERRNO(BT_LOG_ERROR, _init_msg, _fmt, ##__VA_ARGS__)
#define BT_CLOGW_ERRNO(_init_msg, _fmt, ...)                                                       \
    BT_CLOG_ERRNO(BT_LOG_WARNING, _init_msg, _fmt, ##__VA_ARGS__)
#define BT_CLOGI_ERRNO(_init_msg, _fmt, ...)                                                       \
    BT_CLOG_ERRNO(BT_LOG_INFO, _init_msg, _fmt, ##__VA_ARGS__)
#define BT_CLOGD_ERRNO(_init_msg, _fmt, ...)                                                       \
    BT_CLOG_ERRNO(BT_LOG_DEBUG, _init_msg, _fmt, ##__VA_ARGS__)
#define BT_CLOGT_ERRNO(_init_msg, _fmt, ...)                                                       \
    BT_CLOG_ERRNO(BT_LOG_TRACE, _init_msg, _fmt, ##__VA_ARGS__)

/*
 * Logs memory bytes with the level `_lvl` using the configuration
 * `_log_cfg`.
 */
#define BT_CLOG_MEM_EX(_lvl, _log_cfg, _data, _data_sz, _fmt, ...)                                 \
    if (BT_LOG_ON(_lvl)) {                                                                         \
        if ((_log_cfg).selfComp()) {                                                               \
            _bt_log_write_mem((_lvl), BT_LOG_TAG, (_data), (_data_sz),                             \
                              _BT_CLOG_OBJ_FMT_PREFIX _fmt, (_log_cfg).selfCompName(),             \
                              ##__VA_ARGS__);                                                      \
        } else if ((_log_cfg).selfCompCls()) {                                                     \
            _bt_log_write_mem((_lvl), BT_LOG_TAG, (_data), (_data_sz),                             \
                              _BT_CLOG_OBJ_FMT_PREFIX _fmt, (_log_cfg).selfCompClsName(),          \
                              ##__VA_ARGS__);                                                      \
        } else {                                                                                   \
            _bt_log_write_mem((_lvl), BT_LOG_TAG, (_data), (_data_sz), _fmt, ##__VA_ARGS__);       \
        }                                                                                          \
    }

#define BT_CLOGF_MEM_EX(_log_cfg, _data, _data_sz, _fmt, ...)                                      \
    BT_CLOG_MEM_EX(BT_LOG_FATAL, (_log_cfg), (_data), (_data_sz), ##__VA_ARGS__)
#define BT_CLOGE_MEM_EX(_log_cfg, _data, _data_sz, _fmt, ...)                                      \
    BT_CLOG_MEM_EX(BT_LOG_ERROR, (_log_cfg), (_data), (_data_sz), ##__VA_ARGS__)
#define BT_CLOGW_MEM_EX(_log_cfg, _data, _data_sz, _fmt, ...)                                      \
    BT_CLOG_MEM_EX(BT_LOG_WARNING, (_log_cfg), (_data), (_data_sz), ##__VA_ARGS__)
#define BT_CLOGI_MEM_EX(_log_cfg, _data, _data_sz, _fmt, ...)                                      \
    BT_CLOG_MEM_EX(BT_LOG_INFO, (_log_cfg), (_data), (_data_sz), ##__VA_ARGS__)
#define BT_CLOGD_MEM_EX(_log_cfg, _data, _data_sz, _fmt, ...)                                      \
    BT_CLOG_MEM_EX(BT_LOG_DEBUG, (_log_cfg), (_data), (_data_sz), ##__VA_ARGS__)
#define BT_CLOGT_MEM_EX(_log_cfg, _data, _data_sz, _fmt, ...)                                      \
    BT_CLOG_MEM_EX(BT_LOG_TRACE, (_log_cfg), (_data), (_data_sz), ##__VA_ARGS__)
#define BT_CLOGT_MEM(_data, _data_sz, _fmt, ...)                                                   \
    BT_CLOG_MEM_EX(BT_LOG_TRACE, (BT_CLOG_CFG), (_data), (_data_sz), ##__VA_ARGS__)
#define BT_CLOGF_MEM(_data, _data_sz, _fmt, ...)                                                   \
    BT_CLOG_MEM(BT_LOG_FATAL, (_data), (_data_sz), ##__VA_ARGS__)
#define BT_CLOGE_MEM(_data, _data_sz, _fmt, ...)                                                   \
    BT_CLOG_MEM(BT_LOG_ERROR, (_data), (_data_sz), ##__VA_ARGS__)
#define BT_CLOGW_MEM(_data, _data_sz, _fmt, ...)                                                   \
    BT_CLOG_MEM(BT_LOG_WARNING, (_data), (_data_sz), ##__VA_ARGS__)
#define BT_CLOGI_MEM(_data, _data_sz, _fmt, ...)                                                   \
    BT_CLOG_MEM(BT_LOG_INFO, (_data), (_data_sz), ##__VA_ARGS__)
#define BT_CLOGD_MEM(_data, _data_sz, _fmt, ...)                                                   \
    BT_CLOG_MEM(BT_LOG_DEBUG, (_data), (_data_sz), ##__VA_ARGS__)
#define BT_CLOGT_MEM(_data, _data_sz, _fmt, ...)                                                   \
    BT_CLOG_MEM(BT_LOG_TRACE, (_data), (_data_sz), ##__VA_ARGS__)

#endif /* BABELTRACE_CPP_COMMON_CFG_LOGGING_HPP */
