/*
 * Copyright (c) 2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_LOGGING_OBJ_HPP
#define _CTF_SRC_METADATA_JSON_LOGGING_OBJ_HPP

#include "cpp-common/log-cfg.hpp"
#include "cpp-common/text-loc-str.hpp"
#include "../ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Mixin taking care of a logging configuration and a text location
 * string format and offering _locStr() to create a text location string
 * for various objects.
 */
class LoggingObj
{
protected:
    explicit LoggingObj(const bt2_common::LogCfg& logCfg,
                        const bt2_common::TextLocStrFmt textLocStrFmt) :
        _mLogCfg {logCfg},
        _mTextLocStrFmt {textLocStrFmt}
    {
    }

    const bt2_common::LogCfg& _logCfg() const noexcept
    {
        return _mLogCfg;
    }

    bt2_common::TextLocStrFmt _textLocStrFmt() const noexcept
    {
        return _mTextLocStrFmt;
    }

    std::string _locStr(const bt2_common::TextLoc& loc) const
    {
        return bt2_common::textLocStr(loc, _mTextLocStrFmt);
    }

    std::string _locStr(const Fc& fc) const
    {
        return this->_locStr(fc.loc());
    }

    std::string _locStr(const FieldLoc& loc) const
    {
        return this->_locStr(loc.loc());
    }

private:
    bt2_common::LogCfg _mLogCfg;
    bt2_common::TextLocStrFmt _mTextLocStrFmt;
};

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_LOGGING_OBJ_HPP */
