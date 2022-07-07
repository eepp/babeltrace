/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Simon Marchi <simon.marchi@efficios.com>
 * Copyright (c) 2022 Philippe Proulx <eeppeliteloop@gmail.com>
 */

#ifndef BABELTRACE_CPP_COMMON_CFG_LOGGING_ERROR_REPORTING_HPP
#define BABELTRACE_CPP_COMMON_CFG_LOGGING_ERROR_REPORTING_HPP

#include <babeltrace2/babeltrace.h>
#include "cfg-logging.hpp"

/*
 * Logs with the level `_lvl` using the configuration `_log_cfg` and
 * appends a cause to the error of the current thread.
 */
#define BT_CLOGE_APPEND_CAUSE_EX(_log_cfg, _fmt, ...)                                              \
    do {                                                                                           \
        BT_CLOGE_EX((_log_cfg), _fmt, ##__VA_ARGS__);                                              \
        if ((_log_cfg).selfMsgIter()) {                                                            \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_MESSAGE_ITERATOR((_log_cfg).selfMsgIter(),   \
                                                                       _fmt, ##__VA_ARGS__);       \
        } else if ((_log_cfg).selfComp()) {                                                        \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT((_log_cfg).selfComp(), _fmt,       \
                                                                ##__VA_ARGS__);                    \
        } else if ((_log_cfg).selfCompCls()) {                                                     \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT_CLASS((_log_cfg).selfCompCls(),    \
                                                                      _fmt, ##__VA_ARGS__);        \
        } else {                                                                                   \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_UNKNOWN((_log_cfg).moduleName(), _fmt,       \
                                                              ##__VA_ARGS__);                      \
        }                                                                                          \
    } while (false)

#define BT_CLOGE_APPEND_CAUSE(_fmt, ...)                                                           \
    BT_CLOGE_APPEND_CAUSE_EX((BT_CLOG_CFG), _fmt, ##__VA_ARGS__)

/*
 * Logs with the level `_lvl` using the configuration `_log_cfg` and
 * appends a cause to the error of the current thread.
 */
#define BT_CLOGE_STR_APPEND_CAUSE_EX(_log_cfg, _str)                                               \
    do {                                                                                           \
        BT_CLOGE_STR_EX((_log_cfg), _str);                                                         \
        if ((_log_cfg).selfMsgIter()) {                                                            \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_MESSAGE_ITERATOR((_log_cfg).selfMsgIter(),   \
                                                                       "%s", _str);                \
        } else if ((_log_cfg).selfComp()) {                                                        \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT((_log_cfg).selfComp(), "%s",       \
                                                                _str);                             \
        } else if ((_log_cfg).selfCompCls()) {                                                     \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT_CLASS((_log_cfg).selfCompCls(),    \
                                                                      "%s", _str);                 \
        } else {                                                                                   \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_UNKNOWN((_log_cfg).moduleName(), "%s",       \
                                                              _str);                               \
        }                                                                                          \
    } while (false)

#define BT_CLOGE_STR_APPEND_CAUSE(_str) BT_CLOGE_STR_APPEND_CAUSE_EX((BT_CLOG_CFG), _str)

/*
 * Logs an errno message with the level `_lvl`, using the configuration
 * `_log_cfg`, having the initial message `_init_msg`, and appends a
 * cause to the error of the current thread.
 */
#define BT_CLOGE_ERRNO_APPEND_CAUSE_EX(_log_cfg, _init_msg, _fmt, ...)                             \
    do {                                                                                           \
        const auto errStr = g_strerror(errno);                                                     \
        BT_CLOGE_ERRNO_EX((_log_cfg), _init_msg, _fmt, ##__VA_ARGS__);                             \
        if ((_log_cfg).selfMsgIter()) {                                                            \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_MESSAGE_ITERATOR(                            \
                (_log_cfg).selfMsgIter(), "%s: %s" _fmt, _init_msg, errStr, ##__VA_ARGS__);        \
        } else if ((_log_cfg).selfComp()) {                                                        \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT(                                   \
                (_log_cfg).selfComp(), "%s: %s" _fmt, _init_msg, errStr, ##__VA_ARGS__);           \
        } else if ((_log_cfg).selfCompCls()) {                                                     \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT_CLASS(                             \
                (_log_cfg).selfCompCls(), "%s: %s" _fmt, _init_msg, errStr, ##__VA_ARGS__);        \
        } else {                                                                                   \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_UNKNOWN(                                     \
                (_log_cfg).moduleName(), "%s: %s" _fmt, _init_msg, errStr, ##__VA_ARGS__);         \
        }                                                                                          \
    } while (false)

#define BT_CLOGE_ERRNO_APPEND_CAUSE(_init_msg, _fmt, ...)                                          \
    BT_CLOGE_ERRNO_APPEND_CAUSE_EX((BT_CLOG_CFG), _init_msg, _fmt, ##__VA_ARGS__)

/*
 * Logs memory bytes with the level `_lvl` using the configuration
 * `_log_cfg` and appends a cause to the error of the current thread.
 */
#define BT_CLOGE_MEM_APPEND_CAUSE_EX(_log_cfg, _data, _data_sz, _fmt, ...)                         \
    do {                                                                                           \
        const auto errStr = g_strerror(errno);                                                     \
        BT_CLOGE_MEM_EX((_log_cfg), (_data), (_data_sz), _fmt, ##__VA_ARGS__);                     \
        if ((_log_cfg).selfMsgIter()) {                                                            \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_MESSAGE_ITERATOR((_log_cfg).selfMsgIter(),   \
                                                                       _fmt, ##__VA_ARGS__);       \
        } else if ((_log_cfg).selfComp()) {                                                        \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT((_log_cfg).selfComp(), _fmt,       \
                                                                ##__VA_ARGS__);                    \
        } else if ((_log_cfg).selfCompCls()) {                                                     \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_COMPONENT_CLASS((_log_cfg).selfCompCls(),    \
                                                                      _fmt, ##__VA_ARGS__);        \
        } else {                                                                                   \
            BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_UNKNOWN((_log_cfg).moduleName(), _fmt,       \
                                                              ##__VA_ARGS__);                      \
        }                                                                                          \
    } while (false)

#define BT_CLOGE_MEM_APPEND_CAUSE(_data, _data_sz, _fmt, ...)                                      \
    BT_CLOGE_MEM_APPEND_CAUSE_EX((BT_CLOG_CFG), (_data), (_data_sz), _fmt, ##__VA_ARGS__)

#endif /* BABELTRACE_CPP_COMMON_CFG_LOGGING_ERROR_REPORTING_HPP */
