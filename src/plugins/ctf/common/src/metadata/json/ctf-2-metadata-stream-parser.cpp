/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#define BT_LOG_TAG          "PLUGIN/CTF/CTF-2-META-STREAM-PARSER"
#define BT_LOG_OUTPUT_LEVEL _mLogCfg.logLevel()
#include "logging/log.h"

#include <sstream>

#include "common/assert.h"
#include "cpp-common/parse-json-as-val.hpp"
#include "cpp-common/bt2-value-from-json-val.hpp"
#include "cpp-common/comp-logging.hpp"
#include "../finalize-trace-cls.hpp"
#include "ctf-2-metadata-stream-parser.hpp"
#include "scope-fc-from-json-val.hpp"
#include "json-fcs-with-role.hpp"
#include "../../../metadata/json/strings.hpp"
#include "utils.hpp"

namespace ctf {
namespace src {

namespace bt2c = bt2_common;
namespace strings = json_strings;

static inline bt2c::JsonObjVal::UP createDefClkOffsetJsonObjVal()
{
    bt2c::JsonObjVal::Container entries;

    entries.insert(std::make_pair(strings::seconds, bt2c::createJsonVal(0LL, bt2c::TextLoc {})));
    entries.insert(std::make_pair(strings::cycles, bt2c::createJsonVal(0ULL, bt2c::TextLoc {})));
    return bt2c::createJsonVal(std::move(entries), bt2c::TextLoc {});
}

Ctf2MetadataStreamParser::Ctf2MetadataStreamParser(bt_self_component * const selfComp,
                                                   const bt2c::LogCfg& logCfg) :
    MetadataStreamParser {selfComp},
    _mDefClkOffsetVal {createDefClkOffsetJsonObjVal()}, _mLogCfg {logCfg}
{
}

void Ctf2MetadataStreamParser::_parseSection(const std::uint8_t * const begin,
                                             const std::uint8_t * const end)
{
    try {
        this->_parseFragments(begin, end);
    } catch (const bt2_common::TextParseError& err) {
        for (auto& msg : err.msgs()) {
            BT_COMP_OR_COMP_CLASS_LOGE_APPEND_CAUSE(
                _mLogCfg.selfComp(), _mLogCfg.selfCompCls(),
                "[Metadata stream parsing error, at offset %llu] %s", msg.loc().offset(),
                msg.msg().c_str());
        }

        throw bt2::Error {err.what()};
    }
}

void Ctf2MetadataStreamParser::_parseFragments(const std::uint8_t * const begin,
                                               const std::uint8_t * const end)
{
    BT_ASSERT(begin);
    BT_ASSERT(end);
    BT_ASSERT(end >= begin);

    auto fragmentBegin = begin;
    const auto curSectionOffsetInStream = _mCurOffsetInStream;

    while (true) {
        /* Find the beginning pointer of the current JSON fragment */
        while (fragmentBegin != end && *fragmentBegin == 30) {
            /* Skip RS byte */
            ++fragmentBegin;
        }

        _mCurOffsetInStream =
            curSectionOffsetInStream + bt2c::DataLen::fromBytes(fragmentBegin - begin);

        if (fragmentBegin == end) {
            /* We're done */
            return;
        }

        /* Find the end pointer of the current JSON fragment */
        auto fragmentEnd = fragmentBegin;

        while (fragmentEnd != end && *fragmentEnd != 30) {
            /* Skip non-RS byte */
            ++fragmentEnd;
        }

        if (fragmentBegin == fragmentEnd) {
            throw bt2c::TextParseError {"Expecting a fragment.", this->_loc(begin, fragmentBegin)};
        }

        /* Parse one fragment */
        _mCurOffsetInStream =
            curSectionOffsetInStream + bt2c::DataLen::fromBytes(fragmentBegin - begin);
        this->_parseFragment(fragmentBegin, fragmentEnd);

        /* Go to next fragment */
        fragmentBegin = fragmentEnd;
        ++_mCurFragmentIndex;
    }

    /* Adjust offset in metadat stream for the next section to parse */
    _mCurOffsetInStream = curSectionOffsetInStream + bt2c::DataLen::fromBytes(end - begin);
}

void Ctf2MetadataStreamParser::_parseFragment(const std::uint8_t * const begin,
                                              const std::uint8_t * const end)
{
    try {
        this->_handleFragment(bt2c::parseJson(reinterpret_cast<const char *>(begin),
                                              reinterpret_cast<const char *>(end),
                                              _mCurOffsetInStream.bytes()));
    } catch (bt2c::TextParseError& exc) {
        std::ostringstream ss;

        ss << "In fragment #" << (_mCurFragmentIndex + 1) << ':';
        exc.appendErrorMsg(ss.str(), this->_loc(begin, begin));
        throw;
    }
}

void Ctf2MetadataStreamParser::_handleFragment(bt2c::JsonVal::UP jsonFragment)
{
    /* Validate the fragment */
    _mFragmentValReq.validate(*jsonFragment);

    /* Get type */
    auto& jsonFragmentObj = jsonFragment->asObj();
    auto& type = jsonFragmentObj.rawStrVal(strings::type);

    /* Specific preamble fragment case */
    if (_mCurFragmentIndex == 0) {
        if (type != strings::preamble) {
            throwTextParseError("Expecting the preamble fragment.", jsonFragmentObj);
        }

        /* Possibly set the metadata stream UUID */
        _mMetadataStreamUuid = uuidOfObj(jsonFragmentObj);

        /*
         * Nothing more to do with the preamble fragment, but it must
         * exist!
         */
        return;
    }

    /* Defer to specific method */
    if (type == strings::preamble) {
        BT_ASSERT(_mCurFragmentIndex > 0);
        throwTextParseError("Preamble fragment must be the first fragment of the metadata stream.",
                            jsonFragmentObj);
    } else if (type == strings::traceCls) {
        this->_handleTraceClsFragment(std::move(jsonFragment));
    } else if (type == strings::clkCls) {
        this->_handleClkClsFragment(jsonFragmentObj);
    } else if (type == strings::dataStreamCls) {
        this->_handleDataStreamClsFragment(std::move(jsonFragment));
    } else {
        BT_ASSERT(type == strings::eventRecordCls);
        this->_handleEventRecordClsFragment(jsonFragmentObj);
    }
}

void Ctf2MetadataStreamParser::_validatePktHeaderFcRoles(const bt2c::JsonObjVal& jsonPktHeaderFc)
{
    /*
     * Validate that, if an unsigned integer field class FC has a
     * "packet magic number" role:
     *
     * • FC is a 32-bit fixed-length unsigned integer field class.
     *
     * • FC is the field class of the first member class of the the
     *   packet header scope structure field class.
     *
     * • There's only one such FC within the whole packet header scope
     *   field class.
     */
    {
        const auto jsonFcs = jsonFcsWithRole(jsonPktHeaderFc, {strings::pktMagicNumber}, false);

        if (jsonFcs.size() > 1) {
            std::ostringstream ss;

            ss << "Packet header field class may contain zero or one field classes having the role `"
               << strings::pktMagicNumber << "`, not " << jsonFcs.size() << '.';
            throwTextParseError(ss, **jsonFcs.begin());
        }

        if (!jsonFcs.empty()) {
            auto& jsonFc = (*jsonFcs.begin())->asObj();
            auto& jsonType = jsonFc[strings::type]->asStr();

            if (*jsonType != strings::fixedLenUInt && *jsonType != strings::fixedLenUEnum) {
                std::ostringstream ss;

                ss << "Unexpected type of field class having the `" << strings::pktMagicNumber
                   << "` role with the `" << *jsonType << "` type: expecting `"
                   << strings::fixedLenUInt << "` or `" << strings::fixedLenUEnum << "`.";
                throwTextParseError(ss, jsonType);
            }

            auto& jsonLen = jsonFc[strings::len]->asUInt();

            if (*jsonLen != 32) {
                std::ostringstream ss;

                ss << "Unexpected `" << strings::len
                   << "` property of fixed-length unsigned integer field class having the `"
                   << strings::pktMagicNumber << "` role: expecting 32, not " << *jsonLen << '.';
                throwTextParseError(ss, jsonLen);
            }
        }
    }

    /*
     * Validate that, if there's at least one static-length BLOB field
     * class having the "metadata stream UUID" role, then the metadata
     * stream has a UUID.
     */
    {
        const auto jsonFcs = jsonFcsWithRole(jsonPktHeaderFc, {}, true);

        if (!jsonFcs.empty() && !_mMetadataStreamUuid) {
            std::ostringstream ss;

            ss << "Static-length BLOB field class has the role `" << strings::metadataStreamUuid
               << "`, but the preamble fragment of the metadata stream has no `" << strings::uuid
               << "` property.";
            throwTextParseError(ss, **jsonFcs.begin());
        }
    }
}

void Ctf2MetadataStreamParser::_validateTraceClsFragmentRoles(const bt2c::JsonObjVal& jsonFragment)
{
    const auto jsonPktHeaderFc = jsonFragment[strings::pktHeaderFc];

    if (!jsonPktHeaderFc) {
        /*
         * Nothing to validate without a packet header scope field
         * class.
         */
        return;
    }

    try {
        this->_validatePktHeaderFcRoles(jsonPktHeaderFc->asObj());
    } catch (bt2c::TextParseError& exc) {
        exc.appendErrorMsg("Invalid packet header field class:", jsonPktHeaderFc->loc());
        throw;
    }
}

void Ctf2MetadataStreamParser::_handleTraceClsFragment(bt2c::JsonVal::UP jsonFragment)
{
    auto& jsonFragmentObj = jsonFragment->asObj();

    /* Validate field roles */
    try {
        this->_validateTraceClsFragmentRoles(jsonFragmentObj);
    } catch (bt2c::TextParseError& exc) {
        exc.appendErrorMsg("Invalid trace class fragment:", jsonFragmentObj.loc());
        throw;
    }

    /* Check for trace class uniqueness */
    if (_mTraceCls) {
        throwTextParseError("Duplicate trace class fragment.", jsonFragmentObj);
    }

    /* Create the current trace class */
    auto pktHeaderFc =
        this->_scopeFcOfJsonVal(jsonFragmentObj, strings::pktHeaderFc,
                                ir::FieldLocScope::PKT_HEADER, &jsonFragmentObj, nullptr, nullptr);

    _mTraceCls =
        createTraceCls(uuidOfObj(jsonFragmentObj), bt2ValueOfObj(jsonFragmentObj, strings::env),
                       std::move(pktHeaderFc), userAttrsOfObj(jsonFragmentObj));
    _mJsonTraceCls = std::move(jsonFragment);
}

void Ctf2MetadataStreamParser::_handleClkClsFragment(const bt2c::JsonObjVal& jsonFragment)
{
    this->_ensureExistingTraceCls();

    /* Name */
    auto name = jsonFragment.rawStrVal(strings::name);

    if (_mClkClasses.find(name) != _mClkClasses.end()) {
        std::ostringstream ss;

        ss << "Duplicate clock class fragment named `" << name << "`.";
        throwTextParseError(ss, jsonFragment);
    }

    /* Description */
    nonstd::optional<std::string> descr;
    const auto jsonDescrVal = jsonFragment[strings::descr];

    if (jsonDescrVal) {
        descr = *jsonDescrVal->asStr();
    }

    /* Offset */
    auto& jsonOffsetVal = jsonFragment.val(strings::offset, *_mDefClkOffsetVal);
    const auto jsonOffsetSecsVal = jsonOffsetVal[strings::seconds];
    auto offsetSeconds = 0LL;

    if (jsonOffsetSecsVal) {
        offsetSeconds = rawIntValFromJsonIntVal<long long>(*jsonOffsetSecsVal);
    }

    const auto offsetCycles = jsonOffsetVal.rawVal(strings::cycles, 0ULL);

    /* Create corresponding clock class */
    auto clkCls = createClkCls(name, jsonFragment.rawUIntVal(strings::freq),
                               ir::ClkOffset {offsetSeconds, offsetCycles},
                               jsonFragment.rawVal(strings::originIsUnixEpoch, true),
                               std::move(descr), jsonFragment.rawVal(strings::precision, 0ULL),
                               uuidOfObj(jsonFragment), userAttrsOfObj(jsonFragment));

    /* Add to map of clock classes */
    _mClkClasses.emplace(std::make_pair(std::move(name), std::move(clkCls)));
}

static inline nonstd::optional<std::pair<std::string, bt2c::TextLoc>>
optStrOfObjWithLoc(const bt2c::JsonObjVal& jsonObjVal, const std::string& propName)
{
    const auto jsonVal = jsonObjVal[propName];

    if (jsonVal) {
        return std::make_pair(*jsonVal->asStr(), jsonVal->loc());
    }

    return nonstd::nullopt;
}

static inline std::string fullClsId(const unsigned long long id,
                                    const nonstd::optional<std::string>& ns,
                                    const nonstd::optional<std::string>& name)
{
    std::ostringstream ss;

    ss << id;

    if (ns || name) {
        ss << " (";

        if (ns) {
            ss << '`' << *ns << '`';

            if (name) {
                ss << '/';
            }
        }

        if (name) {
            ss << '`' << *name << '`';
        }

        ss << ')';
    }

    return ss.str();
}

template <typename ClsT>
std::string fullClsId(const ClsT& cls)
{
    return fullClsId(cls.id(), cls.ns(), cls.name());
}

void Ctf2MetadataStreamParser::_validateDefClkTsRoles(const bt2c::JsonObjVal& jsonScopeFc,
                                                      const bool hasDefClkCls)
{
    const auto jsonFcs =
        jsonFcsWithRole(jsonScopeFc, {strings::defClkTs, strings::pktEndDefClkTs}, false);

    if (!jsonFcs.empty() && !hasDefClkCls) {
        std::ostringstream ss;

        ss << "Invalid unsigned integer field class having the `" << strings::defClkTs << "` or `"
           << strings::pktEndDefClkTs
           << "` role because its containing data stream class fragment has no default clock class (missing `"
           << strings::defClkClsName << "` property).";
        throwTextParseError(ss, **jsonFcs.begin());
    }
}

void Ctf2MetadataStreamParser::_validateDataStreamClsFragmentRoles(
    const bt2c::JsonObjVal& jsonFragment, const bool hasDefClkCls)
{
    const auto jsonPktCtxFc = jsonFragment[strings::pktCtxFc];

    if (jsonPktCtxFc) {
        try {
            this->_validateDefClkTsRoles(jsonPktCtxFc->asObj(), hasDefClkCls);
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid packet context field class:", jsonPktCtxFc->loc());
            throw;
        }
    }

    const auto jsonEventRecordHeaderFc = jsonFragment[strings::eventRecordHeaderFc];

    if (jsonEventRecordHeaderFc) {
        try {
            this->_validateDefClkTsRoles(jsonEventRecordHeaderFc->asObj(), hasDefClkCls);
        } catch (bt2c::TextParseError& exc) {
            exc.appendErrorMsg("Invalid event record header field class:",
                               jsonEventRecordHeaderFc->loc());
            throw;
        }
    }
}

void Ctf2MetadataStreamParser::_handleDataStreamClsFragment(bt2c::JsonVal::UP jsonFragment)
{
    this->_ensureExistingTraceCls();

    /* ID */
    auto& jsonFragmentObj = jsonFragment->asObj();
    const auto id = jsonFragmentObj.rawVal(strings::id, 0ULL);

    if ((*_mTraceCls)[id]) {
        std::ostringstream ss;

        ss << "Duplicate data stream class fragment with ID " << id << '.';
        throwTextParseError(ss, jsonFragmentObj);
    }

    /* Default clock class name */
    const auto defClkClsName = optStrOfObjWithLoc(jsonFragmentObj, strings::defClkClsName);
    ClkCls::SP defClkCls;

    if (defClkClsName) {
        const auto it = _mClkClasses.find(defClkClsName->first);

        if (it == _mClkClasses.end()) {
            std::ostringstream ss;

            ss << '`' << defClkClsName->first << "` doesn't name an existing clock class fragment.";
            throw bt2c::TextParseError {ss.str(), defClkClsName->second};
        }

        defClkCls = it->second;
    }

    /* Namespace and name */
    const auto ns = optStrOfObj(jsonFragmentObj, strings::ns);
    const auto name = optStrOfObj(jsonFragmentObj, strings::name);

    /* Validate field roles and create data stream class */
    try {
        /* Validate field roles */
        this->_validateDataStreamClsFragmentRoles(jsonFragmentObj, defClkClsName.has_value());

        /* Create data stream class */
        auto pktCtxFc = this->_dataStreamClsScopeFcOfJsonVal(jsonFragmentObj, strings::pktCtxFc,
                                                             ir::FieldLocScope::PKT_CTX);
        auto eventRecordHeaderFc = this->_dataStreamClsScopeFcOfJsonVal(
            jsonFragmentObj, strings::eventRecordHeaderFc, ir::FieldLocScope::EVENT_RECORD_HEADER);
        auto commonEventRecordCtxFc =
            this->_dataStreamClsScopeFcOfJsonVal(jsonFragmentObj, strings::eventRecordCommonCtxFc,
                                                 ir::FieldLocScope::EVENT_RECORD_COMMON_CTX);
        auto dataStreamCls =
            createDataStreamCls(id, ns, name, std::move(pktCtxFc), std::move(eventRecordHeaderFc),
                                std::move(commonEventRecordCtxFc), std::move(defClkCls),
                                userAttrsOfObj(jsonFragmentObj));

        /* Map data stream class to its JSON value */
        BT_ASSERT(_mJsonDataStreamClasses.find(dataStreamCls.get()) ==
                  _mJsonDataStreamClasses.end());
        _mJsonDataStreamClasses.emplace(
            std::make_pair(dataStreamCls.get(), std::move(jsonFragment)));

        /* Add data stream class to current trace class */
        _mTraceCls->addDataStreamCls(std::move(dataStreamCls));
    } catch (bt2c::TextParseError& exc) {
        std::ostringstream ss;

        ss << "Invalid data stream class fragment " << fullClsId(id, ns, name) << ':';
        exc.appendErrorMsg(ss.str(), jsonFragmentObj.loc());
        throw;
    }
}

void Ctf2MetadataStreamParser::_handleEventRecordClsFragment(const bt2c::JsonObjVal& jsonFragment)
{
    this->_ensureExistingTraceCls();

    /* Data stream class ID */
    const auto jsonDataStreamClsIdVal = jsonFragment[strings::dataStreamClsId];
    const auto dataStreamClsId = jsonDataStreamClsIdVal ? *jsonDataStreamClsIdVal->asUInt() : 0ULL;
    auto dataStreamCls = (*_mTraceCls)[dataStreamClsId];

    if (!dataStreamCls) {
        std::ostringstream ss;

        ss << "No data stream class fragment exists with ID " << dataStreamClsId << '.';
        throwTextParseError(ss, jsonDataStreamClsIdVal ? *jsonDataStreamClsIdVal : jsonFragment);
    }

    /* ID */
    const auto jsonIdVal = jsonFragment[strings::id];
    const auto id = jsonIdVal ? *jsonIdVal->asUInt() : 0ULL;

    if ((*dataStreamCls)[id]) {
        std::ostringstream ss;

        ss << "Duplicate event record class fragment with ID " << id
           << " within data stream class fragment " << fullClsId(*dataStreamCls) << '.';
        throwTextParseError(ss, jsonIdVal ? *jsonIdVal : jsonFragment);
    }

    /* Create event record class */
    const auto ns = optStrOfObj(jsonFragment, strings::ns);
    const auto name = optStrOfObj(jsonFragment, strings::name);

    try {
        auto specCtxFc = this->_eventRecordClsScopeFcOfJsonVal(
            jsonFragment, strings::specCtxFc, ir::FieldLocScope::EVENT_RECORD_SPEC_CTX,
            *dataStreamCls);
        auto payloadFc = this->_eventRecordClsScopeFcOfJsonVal(
            jsonFragment, strings::payloadFc, ir::FieldLocScope::EVENT_RECORD_PAYLOAD,
            *dataStreamCls);
        auto eventRecordCls = createEventRecordCls(
            id, ns, name, std::move(specCtxFc), std::move(payloadFc), userAttrsOfObj(jsonFragment));

        /* Add event record class to data stream class */
        dataStreamCls->addEventRecordCls(std::move(eventRecordCls));
    } catch (bt2c::TextParseError& exc) {
        std::ostringstream ss;

        ss << "Invalid event record class fragment " << fullClsId(id, ns, name) << ':';
        exc.appendErrorMsg(ss.str(), jsonFragment.loc());

        auto& jsonDataStreamCls = *_mJsonDataStreamClasses[dataStreamCls];

        ss << "For data stream class fragment " << fullClsId(*dataStreamCls) << ':';
        exc.appendErrorMsg(ss.str(), jsonDataStreamCls.loc());
        throw;
    }
}

void Ctf2MetadataStreamParser::_ensureExistingTraceCls()
{
    if (_mTraceCls) {
        /* Already initialized */
        return;
    }

    /* Create a default CTF 2 trace class */
    _mTraceCls = createTraceCls();
}

Fc::UP Ctf2MetadataStreamParser::_scopeFcOfJsonVal(const bt2c::JsonObjVal& jsonVal,
                                                   const std::string& key,
                                                   const ir::FieldLocScope scope,
                                                   const bt2c::JsonVal * const jsonTraceCls,
                                                   const bt2c::JsonVal * const jsonDataStreamCls,
                                                   const bt2c::JsonVal * const jsonEventRecordCls)
{
    const auto jsonFcVal = jsonVal[key];

    if (!jsonFcVal) {
        return nullptr;
    }

    try {
        return scopeFcFromJsonVal(jsonFcVal->asObj(),
                                  static_cast<const bt2c::JsonObjVal *>(jsonTraceCls),
                                  static_cast<const bt2c::JsonObjVal *>(jsonDataStreamCls),
                                  static_cast<const bt2c::JsonObjVal *>(jsonEventRecordCls));
    } catch (bt2c::TextParseError& exc) {
        std::ostringstream ss;

        ss << "Invalid " << scopeStr(scope) << " scope:";
        exc.appendErrorMsg(ss.str(), jsonVal.loc());
        throw;
    }
}

Fc::UP Ctf2MetadataStreamParser::_eventRecordClsScopeFcOfJsonVal(
    const bt2c::JsonObjVal& jsonEventRecordCls, const std::string& key,
    const ir::FieldLocScope scope, const DataStreamCls& dataStreamCls)
{
    return this->_scopeFcOfJsonVal(jsonEventRecordCls, key, scope, _mJsonTraceCls.get(),
                                   _mJsonDataStreamClasses[&dataStreamCls].get(),
                                   &jsonEventRecordCls);
}

Fc::UP
Ctf2MetadataStreamParser::_dataStreamClsScopeFcOfJsonVal(const bt2c::JsonObjVal& jsonDataStreamCls,
                                                         const std::string& key,
                                                         const ir::FieldLocScope scope)
{
    return this->_scopeFcOfJsonVal(jsonDataStreamCls, key, scope, _mJsonTraceCls.get(),
                                   &jsonDataStreamCls, nullptr);
}

} /* namespace src */
} /* namespace ctf */
