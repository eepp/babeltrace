/*
 * Copyright (c) 2015-2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_TEXT_PARSE_ERROR_HPP
#define BABELTRACE_CPP_COMMON_TEXT_PARSE_ERROR_HPP

#include <vector>
#include <string>
#include <stdexcept>

#include "text-loc.hpp"

namespace bt2_common {

class TextParseError;

/*
 * Single error message of a text parse error.
 */
class TextParseErrorMsg final
{
    friend class TextParseError;

private:
    explicit TextParseErrorMsg(std::string&& msg, TextLoc&& loc);

public:
    /*
     * Source location where this error message occurred.
     */
    const TextLoc& loc() const noexcept
    {
        return _mLoc;
    }

    /*
     * Message.
     */
    const std::string& msg() const noexcept
    {
        return _mMsg;
    }

private:
    std::string _mMsg;
    TextLoc _mLoc;
};

/*
 * Text parse error.
 *
 * An instance is thrown when there's a text parse error.
 *
 * The exception object contains a stack of error messages (in reverse
 * order) which place the error in its parsing context. Each error
 * message has a text location to indicate where it's located in the
 * original text.
*/
class TextParseError final : public std::runtime_error
{
public:
    /*
     * Builds a text parse error with the initial message `initMsg` and
     * the initial text location `initLoc`.
     */
    explicit TextParseError(std::string initMsg, TextLoc initLoc = TextLoc {});

    /*
     * Error messages of this error (first message is the most
     * specific).
     */
    const std::vector<TextParseErrorMsg>& msgs() const noexcept
    {
        return _mMsgs;
    }

    const char *what() const noexcept override
    {
        return _mFullErrorStr.c_str();
    }

    /*
     * Appends the error message `msg` at location `loc` to this error.
     */
    void appendErrorMsg(std::string msg, TextLoc loc = TextLoc {});

private:
    void _buildFullErrorStr();

private:
    /* Error messages: first message is the most specific */
    std::vector<TextParseErrorMsg> _mMsgs;

    /* Needed because what() must return `const char *` */
    std::string _mFullErrorStr;
};

} /* namespace bt2_common */

#endif /* BABELTRACE_CPP_COMMON_TEXT_PARSE_ERROR_HPP */
