/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_PARSE_JSON_HPP
#define BABELTRACE_CPP_COMMON_PARSE_JSON_HPP

#include <unordered_set>
#include <string>
#include <cstring>
#include <sstream>

#include "common/assert.h"
#include "str-scanner.hpp"
#include "text-parse-error.hpp"

namespace bt2_common {
namespace internal {

/*
 * JSON text parser.
 *
 * This parser parses a single JSON value, calling the methods of a JSON
 * event listener of type `ListenerT` for each JSON event.
 *
 * The requirements of `ListenerT` are the following public methods:
 *
 *     void onNull(const TextLoc&);
 *     void onScalarVal(bool, const TextLoc&);
 *     void onScalarVal(unsigned long long, const TextLoc&);
 *     void onScalarVal(long long, const TextLoc&);
 *     void onScalarVal(double, const TextLoc&);
 *     void onScalarVal(const std::string&, const TextLoc&);
 *     void onArrayBegin(const TextLoc&);
 *     void onArrayEnd(const TextLoc&);
 *     void onObjBegin(const TextLoc&);
 *     void onObjKey(const std::string&, const TextLoc&);
 *     void onObjEnd(const TextLoc&);
 *
 * The received text location always indicate the location of the
 * _beginning_ of the text representing the corresponding JSON value.
 *
 * This parser honours the grammar of <https://www.json.org/>, not
 * parsing special floating-point number tokens (`nan`, `inf`, and the
 * rest) or C-style comments.
 */
template <typename ListenerT>
class JsonParser final
{
public:
    /*
     * Builds a JSON text parser, wrapping a string between `begin`
     * (included) and `end` (excluded), and parses it, calling the
     * methods of the JSON event listener `listener`.
     *
     * Throws `TextParseError` when there's a parsing error, including
     * when it can't fully parse the JSON string as a valid JSON value.
     */
    explicit JsonParser(const char *begin, const char *end, ListenerT& listener);

private:
    /*
     * Parses the whole JSON string.
     */
    void _parse();

    /*
     * Expects a JSON value, throwing a text parse error if not found.
     */
    void _expectVal();

    /*
     * Tries to parse `null`, calling the event listener on success.
     */
    bool _tryParseNull();

    /*
     * Tries to parse `true` or `false`, calling the event listener on
     * success.
     */
    bool _tryParseBool();

    /*
     * Tries to parse a JSON number, calling the event listener on
     * success.
     */
    bool _tryParseNumber();

    /*
     * Tries to parse a JSON object key, calling the event listener on
     * success.
     */
    bool _tryParseObjKey();

    /*
     * Tries to parse a JSON string, calling the event listener on
     * success.
     */
    bool _tryParseStr();

    /*
     * Tries to parse a JSON array, calling the event listener on
     * success.
     */
    bool _tryParseArray();

    /*
     * Tries to parse a JSON object, calling the event listener on
     * success.
     */
    bool _tryParseObj();

    /*
     * Expects the specific token `token`, throwing a text parse error
     * if not found.
     */
    void _expectToken(const char * const token)
    {
        if (!_mSs.tryScanToken(token)) {
            std::ostringstream ss;

            ss << "Expecting `" << token << "`.";
            throw TextParseError {ss.str(), _mSs.loc()};
        }
    }

    /*
     * Calls StrScanner::tryScanLitStr() with the JSON-specific escape
     * sequence starting characters.
     */
    const std::string *_tryScanLitStr()
    {
        return _mSs.tryScanLitStr("/bfnrtu");
    }

    /*
     * Returns whether or not the current character of the underlying
     * string scanner looks like the beginning of the fractional or
     * exponent part of a constant real number.
     */
    bool _ssCurCharLikeConstRealFracOrExp() const noexcept
    {
        return *_mSs.at() == '.' || *_mSs.at() == 'E' || *_mSs.at() == 'e';
    }

private:
    /* Underlying string scanner */
    StrScanner _mSs;

    /* JSON event listener */
    ListenerT *_mListener;

    /* Object key sets, one for each JSON object level, to detect duplicates */
    std::vector<std::unordered_set<std::string>> _mKeys;
};

template <typename ListenerT>
JsonParser<ListenerT>::JsonParser(const char * const begin, const char * const end,
                                  ListenerT& listener) :
    _mSs {begin, end},
    _mListener {&listener}
{
    BT_ASSERT(end >= begin);
    this->_parse();
}

template <typename ListenerT>
void JsonParser<ListenerT>::_expectVal()
{
    if (this->_tryParseNull()) {
        return;
    }

    if (this->_tryParseBool()) {
        return;
    }

    if (this->_tryParseStr()) {
        return;
    }

    if (this->_tryParseArray()) {
        return;
    }

    if (this->_tryParseObj()) {
        return;
    }

    if (this->_tryParseNumber()) {
        return;
    }

    throw TextParseError {
        "Expecting a JSON value: `null`, `true`, `false`, a supported number "
        "(for an integer: -9,223,372,036,854,775,808 to 18,446,744,073,709,551,615), "
        "`\"` (a string), `[` (an array), or `{` (an object).",
        _mSs.loc()};
}

template <typename ListenerT>
void JsonParser<ListenerT>::_parse()
{
    /* Expect a single JSON value */
    this->_expectVal();

    /* Skip trailing whitespaces */
    _mSs.skipWhitespaces();

    /* Make sure all the text is consumed */
    if (!_mSs.isDone()) {
        throw TextParseError {"Extra data after parsed JSON value.", _mSs.loc()};
    }
}

template <typename ListenerT>
bool JsonParser<ListenerT>::_tryParseNull()
{
    _mSs.skipWhitespaces();

    const auto loc = _mSs.loc();

    if (_mSs.tryScanToken("null")) {
        _mListener->onNull(loc);
        return true;
    }

    return false;
}

template <typename ListenerT>
bool JsonParser<ListenerT>::_tryParseBool()
{
    _mSs.skipWhitespaces();

    const auto loc = _mSs.loc();

    if (_mSs.tryScanToken("true")) {
        _mListener->onScalarVal(true, loc);
        return true;
    } else if (_mSs.tryScanToken("false")) {
        _mListener->onScalarVal(false, loc);
        return true;
    }

    return false;
}

template <typename ListenerT>
bool JsonParser<ListenerT>::_tryParseNumber()
{
    _mSs.skipWhitespaces();

    const auto loc = _mSs.loc();

    /*
     * The `_mSs.tryScanConstReal()` call below is somewhat expensive
     * currently because it involves calling std::regex_search() to
     * confirm the constant real number form.
     *
     * The strategy below is to:
     *
     * 1. Keep the current position P of the string scanner.
     *
     * 2. Call `_mSs.tryScanConstUInt()` and
     *    `_mSs.tryScanConstSInt()` first.
     *
     *    If either one succeeds, make sure the scanned JSON number
     *    can't be in fact a real number. If it can, then reset the
     *    position of the string scanner to P. It's safe to reset the
     *    string scanner position at this point because
     *    `_mSs.skipWhitespaces()` was called above and the constant
     *    number scanning methods won't scan a newline character.
     *
     * 3. Call `_mSs.tryScanConstReal()` last.
     */
    const auto at = _mSs.at();

    if (const auto uIntVal = _mSs.tryScanConstUInt()) {
        if (!this->_ssCurCharLikeConstRealFracOrExp()) {
            /* Confirmed unsigned integer form */
            _mListener->onScalarVal(*uIntVal, loc);
            return true;
        }

        /* Looks like a constant real number: backtrack */
        _mSs.at(at);
    } else if (const auto sIntVal = _mSs.tryScanConstSInt()) {
        if (!this->_ssCurCharLikeConstRealFracOrExp()) {
            /* Confirmed signed integer form */
            _mListener->onScalarVal(*sIntVal, loc);
            return true;
        }

        /* Looks like a constant real number: backtrack */
        _mSs.at(at);
    }

    if (const auto realVal = _mSs.tryScanConstReal()) {
        _mListener->onScalarVal(*realVal, loc);
        return true;
    }

    return false;
}

template <typename ListenerT>
bool JsonParser<ListenerT>::_tryParseStr()
{
    _mSs.skipWhitespaces();

    const auto loc = _mSs.loc();

    if (const auto str = this->_tryScanLitStr()) {
        _mListener->onScalarVal(*str, loc);
        return true;
    }

    return false;
}

template <typename ListenerT>
bool JsonParser<ListenerT>::_tryParseObjKey()
{
    _mSs.skipWhitespaces();

    const auto loc = _mSs.loc();

    if (const auto str = this->_tryScanLitStr()) {
        /* _tryParseObj() pushes */
        BT_ASSERT(!_mKeys.empty());

        /* Insert, checking for duplicate key */
        if (!_mKeys.back().insert(*str).second) {
            std::ostringstream ss;

            ss << "Duplicate JSON object key `" << *str << "`.";
            throw TextParseError {ss.str(), loc};
        }

        _mListener->onObjKey(*str, loc);
        return true;
    }

    return false;
}

template <typename ListenerT>
bool JsonParser<ListenerT>::_tryParseArray()
{
    _mSs.skipWhitespaces();

    const auto loc = _mSs.loc();

    if (!_mSs.tryScanToken("[")) {
        return false;
    }

    /* Beginning of array */
    _mListener->onArrayBegin(loc);

    if (_mSs.tryScanToken("]")) {
        /* Empty array */
        _mListener->onArrayEnd(loc);
        return true;
    }

    while (true) {
        /* Expect array element */
        this->_expectVal();

        if (!_mSs.tryScanToken(",")) {
            /* No more array elements */
            break;
        }
    }

    /* End of array */
    this->_expectToken("]");
    _mListener->onArrayEnd(loc);
    return true;
}

template <typename ListenerT>
bool JsonParser<ListenerT>::_tryParseObj()
{
    _mSs.skipWhitespaces();

    const auto loc = _mSs.loc();

    if (!_mSs.tryScanToken("{")) {
        return false;
    }

    /* Beginning of object */
    _mListener->onObjBegin(loc);

    if (_mSs.tryScanToken("}")) {
        /* Empty object */
        _mListener->onObjEnd(loc);
        return true;
    }

    /* New level of object keys */
    _mKeys.push_back({});

    while (true) {
        /* Expect object key */
        _mSs.skipWhitespaces();

        if (!this->_tryParseObjKey()) {
            throw TextParseError {"Expecting a JSON object key (double-quoted string).",
                                  _mSs.loc()};
        }

        /* Expect colon */
        this->_expectToken(":");

        /* Expect entry value */
        this->_expectVal();

        if (!_mSs.tryScanToken(",")) {
            /* No more entries */
            break;
        }
    }

    /* End of object */
    BT_ASSERT(!_mKeys.empty());
    _mKeys.pop_back();
    this->_expectToken("}");
    _mListener->onObjEnd(loc);
    return true;
}

} /* namespace internal */

/*
 * Parses the JSON text between `begin` and `end` (excluded), calling
 * the methods of `listener` for each JSON event (see
 * `internal::JsonParser` for the requirements of `ListenerT`).
 *
 * Throws `TextParseError` on error.
 */
template <typename ListenerT>
void parseJson(const char * const begin, const char * const end, ListenerT& listener)
{
    internal::JsonParser<ListenerT> {begin, end, listener};
}

/*
 * Parses the null-terminated JSON text `str`, calling the methods of
 * `listener` for each JSON event (see `internal::JsonParser` for the
 * requirements of `ListenerT`).
 *
 * Throws `TextParseError` on error.
 */
template <typename ListenerT>
void parseJson(const char * const str, ListenerT& listener)
{
    parseJson(str, str + std::strlen(str), listener);
}

/*
 * Parses the JSON text `str`, calling the methods of `listener` for
 * each JSON event (see `internal::JsonParser` for the requirements of
 * `ListenerT`).
 *
 * Throws `TextParseError` on error.
 */
template <typename ListenerT>
void parseJson(const std::string& str, ListenerT& listener)
{
    parseJson(str.data(), str.data() + str.size(), listener);
}

} /* namespace bt2_common */

#endif /* BABELTRACE_CPP_COMMON_PARSE_JSON_HPP */
