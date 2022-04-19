/*
 * Copyright (c) 2022 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_COMP_LOGGING_HPP
#define BABELTRACE_CPP_COMMON_COMP_LOGGING_HPP

#include "logging/comp-logging.h"

#define BT_COMP_LOGE_APPEND_CAUSE_AND_THROW(_exc_cls, _self_comp, _fmt, ...)                       \
    do {                                                                                           \
        BT_COMP_LOGE_APPEND_CAUSE((_self_comp), _fmt, ##__VA_ARGS__);                              \
        throw _exc_cls {};                                                                         \
    } while (0)

#define BT_COMP_LOGE_APPEND_CAUSE_AND_RETHROW(_self_comp, _fmt, ...)                               \
    do {                                                                                           \
        BT_COMP_LOGE_APPEND_CAUSE((_self_comp), _fmt, ##__VA_ARGS__);                              \
        throw;                                                                                     \
    } while (0)

#define BT_COMP_CLASS_LOGE_APPEND_CAUSE_AND_THROW(_exc_cls, _self_comp_class, _fmt, ...)           \
    do {                                                                                           \
        BT_COMP_CLASS_LOGE_APPEND_CAUSE((_self_comp_class), _fmt, ##__VA_ARGS__);                  \
        throw _exc_cls {};                                                                         \
    } while (0)

#define BT_COMP_CLASS_LOGE_APPEND_CAUSE_AND_RETHROW(_self_comp_class, _fmt, ...)                   \
    do {                                                                                           \
        BT_COMP_CLASS_LOGE_APPEND_CAUSE((_self_comp_class), _fmt, ##__VA_ARGS__);                  \
        throw;                                                                                     \
    } while (0)

#define BT_COMP_OR_COMP_CLASS_LOGE_APPEND_CAUSE_AND_THROW(_exc_cls, _self_comp, _self_comp_class,  \
                                                          _fmt, ...)                               \
    do {                                                                                           \
        BT_COMP_OR_COMP_CLASS_LOGE_APPEND_CAUSE((_self_comp), (_self_comp_class), _fmt,            \
                                                ##__VA_ARGS__);                                    \
        throw _exc_cls {};                                                                         \
    } while (0)

#define BT_COMP_OR_COMP_CLASS_LOGE_APPEND_CAUSE_AND_RETHROW(_self_comp, _self_comp_class, _fmt,    \
                                                            ...)                                   \
    do {                                                                                           \
        BT_COMP_OR_COMP_CLASS_LOGE_APPEND_CAUSE((_self_comp), (_self_comp_class), _fmt,            \
                                                ##__VA_ARGS__);                                    \
        throw;                                                                                     \
    } while (0)

#endif /* BABELTRACE_CPP_COMMON_COMP_LOGGING_HPP */