/*
 * Copyright (c) 2016-2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "common/common.h"
#include "common/assert.h"

#include "parse-json-as-val.hpp"
#include "text-parse-error.hpp"

namespace bt2_common {

/*
 * Listener for the listener version of parseJson() which iteratively
 * builds a "root" JSON value.
 */
class JsonValBuilder final
{
public:
    explicit JsonValBuilder(const std::size_t baseOffset) : _mBaseOffset {baseOffset}
    {
    }

    void onNull(const TextLoc& loc)
    {
        this->_handleVal(loc);
    }

    template <typename ValT>
    void onScalarVal(const ValT& val, const TextLoc& loc)
    {
        this->_handleVal(loc, val);
    }

    void onArrayBegin(const TextLoc&)
    {
        _mStack.push_back(_StackFrame {_State::IN_ARRAY});
    }

    void onArrayEnd(const TextLoc& loc)
    {
        auto arrayValCont = std::move(this->_stackTop().arrayValCont);

        _mStack.pop_back();
        this->_handleVal(loc, std::move(arrayValCont));
    }

    void onObjBegin(const TextLoc&)
    {
        _mStack.push_back(_StackFrame {_State::IN_OBJ});
    }

    void onObjKey(const std::string& key, const TextLoc&)
    {
        this->_stackTop().lastObjKey = key;
    }

    void onObjEnd(const TextLoc& loc)
    {
        auto objValCont = std::move(this->_stackTop().objValCont);

        _mStack.pop_back();
        this->_handleVal(loc, std::move(objValCont));
    }

    JsonVal::UP releaseVal() noexcept
    {
        return std::move(_mJsonVal);
    }

private:
    /* The state of a stack frame */
    enum class _State
    {
        IN_ARRAY,
        IN_OBJ,
    };

    /* A entry of `_mStack` */
    struct _StackFrame
    {
        explicit _StackFrame(const _State stateParam) : state {stateParam}
        {
        }

        _State state;
        JsonArrayVal::Container arrayValCont;
        JsonObjVal::Container objValCont;
        std::string lastObjKey;
    };

private:
    /*
     * Top frame of the stack.
     */
    _StackFrame& _stackTop() noexcept
    {
        BT_ASSERT_DBG(!_mStack.empty());
        return _mStack.back();
    }

    template <typename... ArgTs>
    void _handleVal(const TextLoc& loc, ArgTs&&...args)
    {
        /* Create a JSON value from custom arguments and `loc` */
        auto jsonVal =
            createJsonVal(std::forward<ArgTs>(args)...,
                          TextLoc {loc.offset() + _mBaseOffset, loc.lineNo(), loc.colNo()});

        if (_mStack.empty()) {
            /* Assign as root */
            _mJsonVal = std::move(jsonVal);
            return;
        }

        switch (_mStack.back().state) {
        case _State::IN_ARRAY:
            /* Append to current JSON array value container */
            this->_stackTop().arrayValCont.push_back(std::move(jsonVal));
            break;

        case _State::IN_OBJ:
            /*
             * Insert into current JSON object value container
             *
             * It's safe to move `this->_stackTop().lastObjKey` as it's
             * only used once.
             */
            this->_stackTop().objValCont.insert(
                std::make_pair(std::move(this->_stackTop().lastObjKey), std::move(jsonVal)));
            break;

        default:
            bt_common_abort();
        }
    }

private:
    std::size_t _mBaseOffset;
    std::vector<_StackFrame> _mStack;
    JsonVal::UP _mJsonVal;
};

JsonVal::UP parseJson(const char * const begin, const char * const end,
                      const std::size_t baseOffset)
{
    JsonValBuilder builder {baseOffset};

    try {
        parseJson(begin, end, builder);
    } catch (const TextParseError& exc) {
        /*
         * Throw similar exception, but with the text location adjusted
         * with `baseOffset`.
         *
         * When the parseJson() call above throws `TextParseError`, the
         * exception contains a single message.
         */
        BT_ASSERT(exc.msgs().size() == 1);

        auto& msg = exc.msgs().front();

        throw TextParseError {msg.msg(), TextLoc {msg.loc().offset() + baseOffset,
                                                  msg.loc().lineNo(), msg.loc().colNo()}};
    }

    return builder.releaseVal();
}

} /* namespace bt2_common */
