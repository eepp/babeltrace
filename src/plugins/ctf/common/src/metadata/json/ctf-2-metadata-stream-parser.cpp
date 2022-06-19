/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#define BT_LOG_TAG  "PLUGIN/CTF/CTF-2-META-STREAM-PARSER"
#define BT_CLOG_CFG _mLogCfg
#include "cpp-common/cfg-logging-error-reporting.hpp"

#include <sstream>

#include "common/assert.h"
#include "cpp-common/parse-json-as-val.hpp"
#include "cpp-common/bt2-value-from-json-val.hpp"
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

Ctf2MetadataStreamParser::Ctf2MetadataStreamParser(const ClkClsCfg& clkClsCfg,
                                                   bt_self_component * const selfComp,
                                                   const bt2c::LogCfg& logCfg) :
    MetadataStreamParser {clkClsCfg, selfComp},
    _mFragmentValReq {logCfg, bt2c::TextLocStrFmt::OFFSET},
    _mDefClkOffsetVal {createDefClkOffsetJsonObjVal()}, _mLogCfg {logCfg}
{
}

MetadataStreamParser::ParseRet Ctf2MetadataStreamParser::parse(const ClkClsCfg& clkClsCfg,
                                                               bt_self_component * const selfComp,
                                                               const uint8_t * const begin,
                                                               const uint8_t * const end,
                                                               const bt2_common::LogCfg& logCfg)
{
    Ctf2MetadataStreamParser parser {clkClsCfg, selfComp, logCfg};

    parser.parseSection(begin, end);

    if (!parser.traceCls() || parser.traceCls()->dataStreamClasses().empty()) {
        /*
         * CTF 2 requires that a metadata stream contains at least one
         * data stream class fragment: `parser.traceCls()`, if it
         * exists, doesn't at this point and we know that `begin` to
         * `end` contains the whole metadata stream.
         */
        BT_CLOGE_APPEND_CAUSE_AND_THROW_EX(
            logCfg, bt2::Error, "Missing data stream class fragment in metadata stream.");
    }

    return std::make_pair(parser.releaseTraceCls(), parser.metadataStreamUuid());
}

void Ctf2MetadataStreamParser::_parseSection(const std::uint8_t * const begin,
                                             const std::uint8_t * const end)
{
    this->_parseFragments(begin, end);
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
            BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "[%s] Expecting a fragment.",
                                            textLocStr(this->_loc(begin, fragmentBegin)).c_str());
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
        this->_handleFragment(bt2c::parseJson(
            reinterpret_cast<const char *>(begin), reinterpret_cast<const char *>(end),
            _mCurOffsetInStream.bytes(), _mLogCfg, bt2c::TextLocStrFmt::OFFSET));
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid fragment #%zu.",
                                          textLocStr(this->_loc(begin, begin)).c_str(),
                                          _mCurFragmentIndex + 1);
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
            BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "[%s] Expecting the preamble fragment.",
                                            textLocStr(jsonFragmentObj).c_str());
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
        BT_CLOGE_APPEND_CAUSE_AND_THROW(
            bt2c::Error,
            "[%s] Preamble fragment must be the first fragment of the metadata stream.",
            textLocStr(jsonFragmentObj).c_str());
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
            BT_CLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error,
                "[%s] Packet header field class may contain zero or one field classes having the role `%s`, not %zu.",
                textLocStr(**jsonFcs.begin()).c_str(), strings::pktMagicNumber, jsonFcs.size());
        }

        if (!jsonFcs.empty()) {
            auto& jsonFc = (*jsonFcs.begin())->asObj();
            auto& jsonType = jsonFc[strings::type]->asStr();

            if (*jsonType != strings::fixedLenUInt && *jsonType != strings::fixedLenUEnum) {
                BT_CLOGE_APPEND_CAUSE_AND_THROW(
                    bt2c::Error,
                    "[%s] Unexpected type of field class having the `%s` role with the `%s` type: "
                    "expecting `%s` or `%s`.",
                    textLocStr(jsonType).c_str(), strings::pktMagicNumber, (*jsonType).c_str(),
                    strings::fixedLenUInt, strings::fixedLenUEnum);
            }

            auto& jsonLen = jsonFc[strings::len]->asUInt();

            if (*jsonLen != 32) {
                BT_CLOGE_APPEND_CAUSE_AND_THROW(
                    bt2c::Error,
                    "[%s] Unexpected `%s` property of fixed-length unsigned integer field class having the `%s` role: "
                    "expecting 32, not %llu.",
                    textLocStr(jsonLen).c_str(), strings::len, strings::pktMagicNumber, *jsonLen);
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
            BT_CLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error,
                "[%s] Static-length BLOB field class has the role `%s`, "
                "but the preamble fragment of the metadata stream has no `%s` property.",
                textLocStr(**jsonFcs.begin()).c_str(), strings::metadataStreamUuid, strings::uuid);
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
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid packet header field class.",
                                          textLocStr(*jsonPktHeaderFc).c_str());
    }
}

void Ctf2MetadataStreamParser::_handleTraceClsFragment(bt2c::JsonVal::UP jsonFragment)
{
    auto& jsonFragmentObj = jsonFragment->asObj();

    /* Validate field roles */
    try {
        this->_validateTraceClsFragmentRoles(jsonFragmentObj);
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid trace class fragment.",
                                          textLocStr(jsonFragmentObj).c_str());
    }

    /* Check for trace class uniqueness */
    if (_mTraceCls) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "[%s] Duplicate trace class fragment.",
                                        textLocStr(jsonFragmentObj).c_str());
    }

    /* Create the current trace class */
    auto pktHeaderFc =
        this->_scopeFcOfJsonVal(jsonFragmentObj, strings::pktHeaderFc,
                                ir::FieldLocScope::PKT_HEADER, &jsonFragmentObj, nullptr, nullptr);

    _mTraceCls =
        createTraceCls(uuidOfObj(jsonFragmentObj), bt2ValueOfObj(jsonFragmentObj, strings::env),
                       std::move(pktHeaderFc), userAttrsOfObj(jsonFragmentObj));

    /*
     * An LTTng clock always has a Unix epoch origin even though the
     * class indicates otherwise.
     */
    const auto env = _mTraceCls->env();

    if (env) {
        const auto entry = (*env)["tracer_name"];
        static constexpr auto lttngPrefix = "lttng";

        if (entry && entry->isString() &&
            entry->asString().value().substr(0, strlen(lttngPrefix)) == lttngPrefix) {
            /* Save this to adjust future clock classes */
            _mIsLttng = true;

            /* Adjust existing clock classes */
            for (auto& nameClkClsPair : _mClkClasses) {
                nameClkClsPair.second->originIsUnixEpoch(true);
            }
        }
    }

    _mJsonTraceCls = std::move(jsonFragment);
}

void Ctf2MetadataStreamParser::_handleClkClsFragment(const bt2c::JsonObjVal& jsonFragment)
{
    /* Name */
    auto name = jsonFragment.rawStrVal(strings::name);

    if (_mClkClasses.find(name) != _mClkClasses.end()) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                        "[%s] Duplicate clock class fragment named `%s`.",
                                        textLocStr(jsonFragment).c_str(), name.c_str());
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
                               _mIsLttng || jsonFragment.rawVal(strings::originIsUnixEpoch, true),
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
        BT_CLOGE_APPEND_CAUSE_AND_THROW(
            bt2c::Error,
            "[%s] Invalid unsigned integer field class having the `%s` or `%s` role because its containing data stream class fragment has no default clock class (missing `%s` property).",
            textLocStr(**jsonFcs.begin()).c_str(), strings::defClkTs, strings::pktEndDefClkTs,
            strings::defClkClsName);
    }
}

void Ctf2MetadataStreamParser::_validateDataStreamClsFragmentRoles(
    const bt2c::JsonObjVal& jsonFragment, const bool hasDefClkCls)
{
    const auto jsonPktCtxFc = jsonFragment[strings::pktCtxFc];

    if (jsonPktCtxFc) {
        try {
            this->_validateDefClkTsRoles(jsonPktCtxFc->asObj(), hasDefClkCls);
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid packet context field class.",
                                              textLocStr(*jsonPktCtxFc).c_str());
        }
    }

    const auto jsonEventRecordHeaderFc = jsonFragment[strings::eventRecordHeaderFc];

    if (jsonEventRecordHeaderFc) {
        try {
            this->_validateDefClkTsRoles(jsonEventRecordHeaderFc->asObj(), hasDefClkCls);
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid event record header field class.",
                                              textLocStr(*jsonEventRecordHeaderFc).c_str());
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
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                        "[%s] Duplicate data stream class fragment with ID %llu.",
                                        textLocStr(jsonFragmentObj).c_str(), id);
    }

    /* Default clock class name */
    const auto defClkClsName = optStrOfObjWithLoc(jsonFragmentObj, strings::defClkClsName);
    ClkCls::SP defClkCls;

    if (defClkClsName) {
        const auto it = _mClkClasses.find(defClkClsName->first);

        if (it == _mClkClasses.end()) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error, "[%s] `%s` doesn't name an existing clock class fragment.",
                textLocStr(defClkClsName->second).c_str(), defClkClsName->first.c_str());
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
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid data stream class fragment %s.",
                                          textLocStr(jsonFragmentObj).c_str(),
                                          fullClsId(id, ns, name).c_str());
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
        BT_CLOGE_APPEND_CAUSE_AND_THROW(
            bt2c::Error, "[%s] No data stream class fragment exists with ID %llu.",
            textLocStr(jsonDataStreamClsIdVal ? *jsonDataStreamClsIdVal : jsonFragment).c_str(),
            dataStreamClsId);
    }

    /* ID */
    const auto jsonIdVal = jsonFragment[strings::id];
    const auto id = jsonIdVal ? *jsonIdVal->asUInt() : 0ULL;

    if ((*dataStreamCls)[id]) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(
            bt2c::Error,
            "[%s] Duplicate event record class fragment with ID %llu within data stream class fragment %s.",
            textLocStr(jsonIdVal ? *jsonIdVal : jsonFragment).c_str(), id,
            fullClsId(*dataStreamCls).c_str());
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
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW(
            "[%s] Invalid event record class fragment %s (for data stream class fragment %s).",
            textLocStr(jsonFragment).c_str(), fullClsId(id, ns, name).c_str(),
            fullClsId(*dataStreamCls).c_str());
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
        return scopeFcFromJsonVal(
            jsonFcVal->asObj(), static_cast<const bt2c::JsonObjVal *>(jsonTraceCls),
            static_cast<const bt2c::JsonObjVal *>(jsonDataStreamCls),
            static_cast<const bt2c::JsonObjVal *>(jsonEventRecordCls), _mLogCfg);
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid %s scope.", textLocStr(jsonVal).c_str(),
                                          scopeStr(scope));
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
