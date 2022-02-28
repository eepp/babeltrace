/*
 * Copyright (c) 2015-2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_STR_SCANNER_HPP
#define BABELTRACE_CPP_COMMON_STR_SCANNER_HPP

#include <cstdlib>
#include <limits>
#include <regex>
#include <cmath>
#include <string>
#include <stdexcept>

#include "common/assert.h"
#include "optional.hpp"
#include "text-loc.hpp"

namespace bt2_common {

/*
 * String scanner.
 *
 * A string scanner (lexer) wraps an input string using two `const char`
 * pointers and scans specific characters and sequences of characters,
 * managing a current character pointer.
 *
 * When you call the various tryScan*() methods to try to scan some
 * contents, the methods advance the current character pointer on
 * success. They also automatically skip initial whitespaces.
 */
class StrScanner final
{
public:
    /*
     * Builds a string scanner, wrapping a string between `begin`
     * (inclusive) and `end` (exclusive).
     *
     * NOTE: This string scanner does NOT own the string between `begin`
     * and `end`, so you must make sure that it's still alive when you
     * call its scanning methods.
     */
    explicit StrScanner(const char *begin, const char *end);

    /* Default move/copy constructor/assignment operator */
    StrScanner(const StrScanner&) = default;
    StrScanner(StrScanner&&) = default;
    StrScanner& operator=(const StrScanner&) = default;
    StrScanner& operator=(StrScanner&&) = default;

    /*
     * Returns the current character pointer.
     */
    const char *at() const noexcept
    {
        return _mAt;
    }

    /*
     * Sets the current character pointer.
     *
     * NOTE: This may corrupt the current location (location()) if the
     * string between at() and `at` includes one or more newline
     * characters.
     */
    void at(const char * const at) noexcept
    {
        BT_ASSERT_DBG(at >= _mBegin && at <= _mEnd);
        _mAt = at;
    }

    /*
     * Returns the beginning character pointer, the one with which this
     * string scanner was built.
     */
    const char *begin() const noexcept
    {
        return _mBegin;
    }

    /*
     * Returns the ending character pointer, the one with which this
     * string scanner was built.
     */
    const char *end() const noexcept
    {
        return _mEnd;
    }

    /*
     * Returns the number of characters left until end().
     */
    std::size_t charsLeft() const noexcept
    {
        return _mEnd - _mAt;
    }

    /*
     * Returns the current text location.
     */
    TextLoc loc() const noexcept
    {
        return TextLoc {static_cast<std::size_t>(_mAt - _mBegin), _mNbLines,
                        static_cast<std::size_t>(_mAt - _mLineBegin)};
    }

    /*
     * Returns whether or not the end of the string is reached.
     */
    bool isDone() const noexcept
    {
        return _mAt == _mEnd;
    }

    /*
     * Resets this string scanner, setting the current character pointer
     * to begin().
     */
    void reset();

    /*
     * Tries to scan a double-quoted literal string, considering the
     * characters of `escapeSeqStartList`, `\`, and `"` as escape
     * sequence starting characters, placing the current character
     * pointer after the closing double quote on success.
     *
     * If `escapeSeqStartList` includes `u`, then a `\u` escape sequence
     * is interpreted as in JSON: four hexadecimal characters which
     * represent the value of a single Unicode codepoint.
     *
     * Valid examples:
     *
     *     "salut!"
     *     "en circulation\nYves?"
     *     "\u03c9 often represents angular velocity in physics"
     *
     * Returns the escaped string, without beginning/end double quotes,
     * on success, or `nullptr` if there's no double-quoted literal
     * string (or if the method reaches end() before a closing `"`).
     *
     * Throws `TextParseError` if the method finds an invalid escape
     * sequence or an illegal control character.
     *
     * The returned string remains valid as long as you don't call any
     * method of this object.
     */
    const std::string *tryScanLitStr(const char *escapeSeqStartList);

    /*
     * Tries to scan and decode a constant integer string, possibly
     * negative if `ValT` (either `unsigned long long` or `long long`)
     * is signed.
     *
     * Valid examples:
     *
     *     9283
     *     -42
     *     0
     *
     * Returns `nonstd::nullopt` if the method couldn't scan a constant
     * integer.
     *
     * The current character pointer is placed after this constant
     * integer string on success.
     */
    template <typename ValT>
    nonstd::optional<ValT> tryScanConstInt() noexcept;

    /*
     * Tries to scan and decode a constant unsigned integer string.
     *
     * Returns `nonstd::nullopt` if the method couldn't scan a constant
     * unsigned integer.
     *
     * The current character pointer is placed after this constant
     * unsigned integer string on success.
     */
    nonstd::optional<unsigned long long> tryScanConstUInt() noexcept
    {
        return this->tryScanConstInt<unsigned long long>();
    }

    /*
     * Tries to scan and decode a constant signed integer string,
     * possibly negative.
     *
     * Returns `nonstd::nullopt` if the method couldn't scan a constant
     * signed integer.
     *
     * The current character pointer is placed after this constant
     * signed integer string on success.
     */
    nonstd::optional<long long> tryScanConstSInt() noexcept
    {
        return this->tryScanConstInt<long long>();
    }

    /*
     * Tries to scan and decode a constant real number string, returning
     * `nonstd::nullopt` if not possible.
     *
     * The format of the real number string to scan is the JSON
     * (<https://www.json.org/>) number one, _with_ a fraction or an
     * exponent part. Without a fraction/exponent part, this method
     * returns `nonstd::nullopt`: use tryScanConstInt() to try scanning
     * a constant integer instead.
     *
     * Valid examples:
     *
     *     17.2
     *     -42.192
     *     8e9
     *     17E12
     *     9.14e+6
     *     -13.2777E-4
     *     0.0
     *     -0.0
     *
     * The current character pointer is placed after this constant real
     * number string on success.
     */
    nonstd::optional<double> tryScanConstReal() noexcept;

    /*
     * Tries to scan the specific token `token`, placing the current
     * character pointer after this string and returning `true` on
     * success.
     */
    bool tryScanToken(const char *token) noexcept;

    /*
     * Skips the next whitespaces, updating the current character
     * pointer.
     */
    void skipWhitespaces() noexcept;

private:
    /*
     * Tries to negate `ullVal` as a signed integer value if `ValT` is
     * signed and `negate` is true, returning `nonstd::nullopt` if it
     * can't.
     *
     * Always succeeds when `ValT` is unsigned.
     */
    template <typename ValT>
    static nonstd::optional<ValT> _tryNegateConstInt(unsigned long long ullVal,
                                                     bool negate) noexcept;

    /*
     * Handles a `\u` escape sequence, appending the UTF-8-encoded
     * Unicode character to `_mStrBuf` on success, or throwing
     * `TextParseError` on error.
     *
     * `at` points to the first hexadecimal character after `\u`.
     */
    void _appendEscapedUnicodeChar(const char *at);

    /*
     * Tries to append an escaped character to `_mStrBuf` from the escape
     * sequence characters at the current character pointer, considering
     * the characters of `escapeSeqStartList`, `\`, and `"` as escape
     * sequence starting characters.
     */
    bool _tryAppendEscapedChar(const char *escapeSeqStartList);

    /*
     * Tries to scan any character, returning it and advancing the
     * current character pointer on success, or returning -1 if the
     * current character pointer is end().
     */
    int _tryScanAnyChar() noexcept
    {
        if (this->isDone()) {
            return -1;
        }

        const auto c = *_mAt;

        this->_incrAt();
        return c;
    }

    /*
     * Checks if the current character pointer is a newline, updating
     * the line count and line beginning pointer if so.
     */
    void _checkNewline() noexcept
    {
        if (*_mAt == '\n') {
            ++_mNbLines;
            _mLineBegin = _mAt + 1;
        }
    }

    /*
     * Increments `_mAt` by `count`.
     */
    void _incrAt(const std::size_t count = 1) noexcept
    {
        _mAt += count;
        BT_ASSERT_DBG(_mAt <= _mEnd);
    }

    /*
     * Decrements `_mAt` by `count`.
     */
    void _decrAt(const std::size_t count = 1) noexcept
    {
        _mAt -= count;
        BT_ASSERT_DBG(_mAt >= _mBegin);
    }

private:
    /* Beginning of the substring to scan, given by user */
    const char *_mBegin;

    /* End of the substring to scan, given by user */
    const char *_mEnd;

    /* Current character */
    const char *_mAt;

    /* Beginning of the current line */
    const char *_mLineBegin;

    /* Number of lines scanned so far */
    std::size_t _mNbLines = 0;

    /* String buffer, used by tryScanToken() and tryScanLitStr() */
    std::string _mStrBuf;

    /* Real number string regex */
    static const std::regex _mRealRegex;
};

template <typename ValT>
nonstd::optional<ValT> StrScanner::_tryNegateConstInt(const unsigned long long ullVal,
                                                      const bool negate) noexcept
{
    /* Check for overflow */
    if (std::is_signed<ValT>::value) {
        constexpr auto llMaxAsUll =
            static_cast<unsigned long long>(std::numeric_limits<long long>::max());

        if (negate) {
            if (ullVal > llMaxAsUll + 1) {
                return nonstd::nullopt;
            }
        } else {
            if (ullVal > llMaxAsUll) {
                return nonstd::nullopt;
            }
        }
    }

    /* Success: cast and negate if needed */
    auto val = static_cast<ValT>(ullVal);

    if (negate) {
        val *= static_cast<ValT>(-1);
    }

    return val;
}

template <typename ValT>
nonstd::optional<ValT> StrScanner::tryScanConstInt() noexcept
{
    static_assert(std::is_same<ValT, long long>::value ||
                      std::is_same<ValT, unsigned long long>::value,
                  "`ValT` is `long long` or `unsigned long long`.");

    this->skipWhitespaces();

    /* Backup if we can't scan completely */
    const auto initAt = _mAt;

    /* Scan initial character */
    const auto c = this->_tryScanAnyChar();

    if (c < 0) {
        /* Nothing left */
        return nonstd::nullopt;
    }

    /* Check for negation */
    const bool negate = (c == '-');

    if (negate && !std::is_signed<ValT>::value) {
        /* Can't negate an unsigned integer */
        this->at(initAt);
        return nonstd::nullopt;
    }

    if (!negate) {
        /* No negation: rewind */
        this->_decrAt();
    }

    /*
     * Only allow a digit at this point: std::strtoull() below supports
     * an initial `+`, but this scanner doesn't.
     */
    if (this->isDone() || !std::isdigit(*_mAt)) {
        this->at(initAt);
        return nonstd::nullopt;
    }

    /* Parse */
    char *strEnd = nullptr;
    const auto ullVal = std::strtoull(_mAt, &strEnd, 10);

    if ((ullVal == 0 && _mAt == strEnd) || errno == ERANGE) {
        /* Couldn't parse */
        errno = 0;
        this->at(initAt);
        return nonstd::nullopt;
    }

    /* Negate if needed */
    const auto val = this->_tryNegateConstInt<ValT>(ullVal, negate);

    if (!val) {
        /* Couldn't negate */
        this->at(initAt);
        return nonstd::nullopt;
    }

    /* Success: update character pointer and return value */
    this->at(strEnd);
    return val;
}

} /* namespace bt2_common */

#endif /* BABELTRACE_CPP_COMMON_STR_SCANNER_HPP */
