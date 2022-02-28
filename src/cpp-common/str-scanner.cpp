/*
 * Copyright (c) 2015-2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <ios>
#include <iomanip>
#include <sstream>

#include "str-scanner.hpp"
#include "text-parse-error.hpp"

namespace bt2_common {

const std::regex StrScanner::_mRealRegex {
    "^"                   /* Start of target */
    "-?"                  /* Optional negation */
    "(?:0|[1-9]\\d*)"     /* Integer part */
    "(?=[eE.]\\d)"        /* Assertion: need fraction/exponent part */
    "(?:\\.\\d+)?"        /* Optional fraction part */
    "(?:[eE][+-]?\\d+)?", /* Optional exponent part */
    std::regex::optimize};

StrScanner::StrScanner(const char * const begin, const char * const end) :
    _mBegin {begin}, _mEnd {end}, _mAt {begin}, _mLineBegin {begin}
{
}

void StrScanner::reset()
{
    this->at(_mBegin);
    _mNbLines = 0;
    _mLineBegin = _mBegin;
}

void StrScanner::skipWhitespaces() noexcept
{
    while (!this->isDone()) {
        switch (*_mAt) {
        case '\n':
            this->_checkNewline();
            /* Fall through */
        case ' ':
        case '\t':
        case '\v':
        case '\r':
            this->_incrAt();
            break;
        default:
            return;
        }
    }
}

void StrScanner::_appendEscapedUnicodeChar(const char * const at)
{
    /* Create array of four hex characters */
    const std::string hexCpBuf {at, at + 4};

    /* Validate hex characters */
    for (const auto ch : hexCpBuf) {
        if (!std::isxdigit(ch)) {
            std::ostringstream ss;

            ss << "In `\\u` escape sequence: unexpected character `" << ch << "`.";
            throw TextParseError {ss.str().c_str(), this->loc()};
        }
    }

    /* Convert hex characters to integral codepoint (always works) */
    const auto cp = std::strtoull(hexCpBuf.data(), nullptr, 16);

    /*
     * Append UTF-8 bytes from integral codepoint.
     *
     * See <https://en.wikipedia.org/wiki/UTF-8#Encoding>.
     */
    if (cp <= 0x7f) {
        _mStrBuf.push_back(cp);
    } else if (cp <= 0x7ff) {
        _mStrBuf.push_back(static_cast<char>((cp >> 6) + 0xc0));
        _mStrBuf.push_back(static_cast<char>((cp & 0x3f) + 0x80));
    } else if (cp > 0xd800 && cp <= 0xdfff) {
        /* Unsupported surrogate pairs */
        std::ostringstream ss;

        ss << "In `\\u` escape sequence: unsupported surrogate codepoint U+" << std::hex << cp
           << ".";
        throw TextParseError {ss.str().c_str(), this->loc()};
    } else {
        BT_ASSERT(cp <= 0xffff);
        _mStrBuf.push_back(static_cast<char>((cp >> 12) + 0xe0));
        _mStrBuf.push_back(static_cast<char>(((cp >> 6) & 0x3f) + 0x80));
        _mStrBuf.push_back(static_cast<char>((cp & 0x3f) + 0x80));
    }
}

bool StrScanner::_tryAppendEscapedChar(const char * const escapeSeqStartList)
{
    if (this->charsLeft() < 2) {
        /* Need at least `\` and another character */
        return false;
    }

    if (_mAt[0] != '\\') {
        /* Not an escape sequence */
        return false;
    }

    auto escapeSeqStart = escapeSeqStartList;

    /* Try each character of `escapeSeqStartList` */
    while (*escapeSeqStart != '\0') {
        if (_mAt[1] == '"' || _mAt[1] == '\\' || _mAt[1] == *escapeSeqStart) {
            /* Escape sequence detected */
            if (_mAt[1] == 'u') {
                /* `\u` escape sequence */
                if (this->charsLeft() < 6) {
                    /* Need `\u` + four hex characters */
                    throw TextParseError {"`\\u` escape sequence needs four hexadecimal digits.",
                                          this->loc()};
                }

                this->_appendEscapedUnicodeChar(_mAt + 2);
                this->_incrAt(6);
            } else {
                /* Single-character escape sequence */
                switch (_mAt[1]) {
                case 'a':
                    _mStrBuf.push_back('\a');
                    break;
                case 'b':
                    _mStrBuf.push_back('\b');
                    break;
                case 'f':
                    _mStrBuf.push_back('\f');
                    break;
                case 'n':
                    _mStrBuf.push_back('\n');
                    break;
                case 'r':
                    _mStrBuf.push_back('\r');
                    break;
                case 't':
                    _mStrBuf.push_back('\t');
                    break;
                case 'v':
                    _mStrBuf.push_back('\v');
                    break;
                default:
                    /* As is */
                    _mStrBuf.push_back(_mAt[1]);
                    break;
                }

                this->_incrAt(2);
            }

            return true;
        }

        ++escapeSeqStart;
    }

    return false;
}

const std::string *StrScanner::tryScanLitStr(const char * const escapeSeqStartList)
{
    this->skipWhitespaces();

    /* Backup if we can't completely scan */
    const auto initAt = _mAt;
    const auto initLineBegin = _mLineBegin;
    const auto initNbLines = _mNbLines;

    /* First character: `"` or alpha */
    auto c = this->_tryScanAnyChar();

    if (c < 0) {
        return nullptr;
    }

    if (c != '"') {
        /* Not a literal string */
        this->at(initAt);
        _mLineBegin = initLineBegin;
        _mNbLines = initNbLines;
        return nullptr;
    }

    /* Reset string buffer */
    _mStrBuf.clear();

    /*
     * Scan inner string, processing escape sequences during the
     * process.
     */
    while (!this->isDone()) {
        /* Check for illegal control character */
        if (std::iscntrl(*_mAt)) {
            std::ostringstream ss;

            ss << "Illegal control character 0x" << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<unsigned int>(*_mAt) << " in literal string.";
            throw TextParseError {ss.str(), this->loc()};
        }

        /* Try to append an escaped character first */
        if (this->_tryAppendEscapedChar(escapeSeqStartList)) {
            continue;
        }

        /* End of literal string? */
        if (*_mAt == '"') {
            /* Skip `"` */
            this->_incrAt();
            return &_mStrBuf;
        }

        /* Check for newline */
        this->_checkNewline();

        /* Append regular character and go to next one */
        _mStrBuf.push_back(*_mAt);
        this->_incrAt();
    }

    /* Couldn't find end of string */
    this->at(initAt);
    _mLineBegin = initLineBegin;
    _mNbLines = initNbLines;
    return nullptr;
}

bool StrScanner::tryScanToken(const char * const token) noexcept
{
    this->skipWhitespaces();

    /* Backup if we can't completely scan */
    const auto initAt = _mAt;

    /* Try to scan token completely */
    auto tokenAt = token;

    while (*tokenAt != '\0' && _mAt != _mEnd) {
        if (*_mAt != *tokenAt) {
            /* Mismatch */
            this->at(initAt);
            return false;
        }

        this->_incrAt();
        ++tokenAt;
    }

    if (*tokenAt != '\0') {
        /* Wrapped string ends before end of token */
        this->at(initAt);
        return false;
    }

    /* Success */
    return true;
}

nonstd::optional<double> StrScanner::tryScanConstReal() noexcept
{
    this->skipWhitespaces();

    /*
     * Validate JSON number format (with fraction and/or exponent part).
     *
     * This is needed because std::strtod() accepts more formats which
     * JSON doesn't support.
     */
    if (!std::regex_search(_mAt, _mEnd, _mRealRegex)) {
        return nonstd::nullopt;
    }

    /* Parse */
    char *strEnd = nullptr;
    const auto val = std::strtod(_mAt, &strEnd);

    if (val == HUGE_VAL || (val == 0 && _mAt == strEnd) || errno == ERANGE) {
        /* Couldn't parse */
        errno = 0;
        return nonstd::nullopt;
    }

    /* Success: update character pointer and return value */
    this->at(strEnd);
    return val;
}

} /* namespace bt2_common */
