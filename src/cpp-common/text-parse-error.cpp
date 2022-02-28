/*
 * Copyright (c) 2015-2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <sstream>

#include "text-parse-error.hpp"

namespace bt2_common {

TextParseErrorMsg::TextParseErrorMsg(std::string&& msg, TextLoc&& loc) :
    _mMsg {std::move(msg)}, _mLoc {std::move(loc)}
{
}

TextParseError::TextParseError(std::string initMsg, TextLoc initLoc) :
    std::runtime_error {"Parse error"}
{
    this->appendErrorMsg(std::move(initMsg), std::move(initLoc));
}

void TextParseError::appendErrorMsg(std::string msg, TextLoc loc)
{
    _mMsgs.push_back(TextParseErrorMsg {std::move(msg), std::move(loc)});
    this->_buildFullErrorStr();
}

void TextParseError::_buildFullErrorStr()
{
    std::ostringstream ss;

    for (auto it = _mMsgs.rbegin(); it != _mMsgs.rend(); ++it) {
        ss << "[" << it->loc().naturalLineNo() << ":" << it->loc().naturalColNo() << "] "
           << it->msg() << '\n';
    }

    _mFullErrorStr = ss.str();
}

} /* namespace bt2_common */
