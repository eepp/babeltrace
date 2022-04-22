/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#ifndef BABELTRACE_CPP_COMMON_LOG_CFG_HPP
#define BABELTRACE_CPP_COMMON_LOG_CFG_HPP

#include <babeltrace2/babeltrace.h>
#include "common/assert.h"

namespace bt2_common {

class LogCfg final
{
public:
    explicit LogCfg(const bt_logging_level logLevel, bt_self_component * const selfComp) :
        _mLogLevel {logLevel}, _mSelfComp {selfComp}
    {
        BT_ASSERT_DBG(_mSelfComp);
    }

    explicit LogCfg(const bt_logging_level logLevel, bt_self_message_iterator * const selfMsgIter) :
        _mLogLevel {logLevel}, _mSelfMsgIter {selfMsgIter}
    {
        BT_ASSERT_DBG(_mSelfMsgIter);
    }

    explicit LogCfg(const bt_logging_level logLevel, bt_self_component_class * const selfCompCls) :
        _mLogLevel {logLevel}, _mSelfCompCls {selfCompCls}
    {
        BT_ASSERT_DBG(_mSelfCompCls);
    }

    explicit LogCfg(const bt_logging_level logLevel, const char * const moduleName) :
        _mLogLevel {logLevel}, _mModuleName {moduleName}
    {
        BT_ASSERT_DBG(_mModuleName);
    }

    bt_logging_level logLevel() const noexcept
    {
        return _mLogLevel;
    }

    bt_self_component *selfComp() const noexcept
    {
        return _mSelfComp;
    }

    bt_self_component_class *selfCompCls() const noexcept
    {
        return _mSelfCompCls;
    }

    bt_self_message_iterator *selfMsgIter() const noexcept
    {
        return _mSelfMsgIter;
    }

    const char *moduleName() const noexcept
    {
        return _mModuleName;
    }

private:
    bt_logging_level _mLogLevel;
    bt_self_component *_mSelfComp = nullptr;
    bt_self_component_class *_mSelfCompCls = nullptr;
    bt_self_message_iterator *_mSelfMsgIter = nullptr;
    const char *_mModuleName = nullptr;
};

} /* namespace bt2_common */

#endif /* BABELTRACE_CPP_COMMON_LOG_CFG_HPP */
