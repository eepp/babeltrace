/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#define BT_LOG_TAG  "PLUGIN/CTF/CTF-2-META-STREAM-PARSER"
#define BT_CLOG_CFG this->_logCfg()
#include "cpp-common/cfg-logging-error-reporting.hpp"

#include <algorithm>
#include <sstream>

#include "common/assert.h"
#include "cpp-common/contains.hpp"
#include "cpp-common/parse-json-as-val.hpp"
#include "cpp-common/bt2-value-from-json-val.hpp"
#include "ctf-2-metadata-stream-parser.hpp"
#include "fcs-with-role.hpp"
#include "../../../metadata/json/strings.hpp"
#include "utils.hpp"
#include "validate-scope-fc-roles.hpp"
#include "normalize-field-locs.hpp"
#include "resolve-fcs-with-int-sel.hpp"

namespace ctf {
namespace src {

namespace bt2c = bt2_common;
namespace strings = json_strings;

namespace {

bt2c::JsonObjVal::UP createDefClkOffsetJsonObjVal()
{
    bt2c::JsonObjVal::Container entries;

    entries.insert(std::make_pair(strings::seconds, bt2c::createJsonVal(0LL, bt2c::TextLoc {})));
    entries.insert(std::make_pair(strings::cycles, bt2c::createJsonVal(0ULL, bt2c::TextLoc {})));
    return bt2c::createJsonVal(std::move(entries), bt2c::TextLoc {});
}

} /* namespace */

Ctf2MetadataStreamParser::Ctf2MetadataStreamParser(const ClkClsCfg& clkClsCfg,
                                                   bt_self_component * const selfComp,
                                                   const bt2c::LogCfg& logCfg) :
    MetadataStreamParser {clkClsCfg, selfComp},
    LoggingObj {logCfg, bt2c::TextLocStrFmt::OFFSET}, _mFragmentValReq {logCfg,
                                                                        this->_textLocStrFmt()},
    _mDefClkOffsetVal {createDefClkOffsetJsonObjVal()}, _mFcBuilder {logCfg, this->_textLocStrFmt()}
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
            BT_CLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error, "[%s] Expecting a fragment.",
                this->_locStr(this->_loc(begin, fragmentBegin)).c_str());
        }

        /* Parse one fragment */
        _mCurOffsetInStream =
            curSectionOffsetInStream + bt2c::DataLen::fromBytes(fragmentBegin - begin);
        this->_parseFragment(fragmentBegin, fragmentEnd);

        /* Go to next fragment */
        fragmentBegin = fragmentEnd;
        ++_mCurFragmentIndex;
    }

    /* Adjust offset in metadata stream for the next section to parse */
    _mCurOffsetInStream = curSectionOffsetInStream + bt2c::DataLen::fromBytes(end - begin);
}

void Ctf2MetadataStreamParser::_parseFragment(const std::uint8_t * const begin,
                                              const std::uint8_t * const end)
{
    try {
        this->_handleFragment(bt2c::parseJson(
            reinterpret_cast<const char *>(begin), reinterpret_cast<const char *>(end),
            _mCurOffsetInStream.bytes(), this->_logCfg(), this->_textLocStrFmt()));
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid fragment #%zu.",
                                          this->_locStr(this->_loc(begin, begin)).c_str(),
                                          _mCurFragmentIndex + 1);
    }
}

namespace {

/*
 * Returns the UUID of the JSON object value `jsonObjVal`, or
 * `nonstd::nullopt` if there's no such property.
 */
nonstd::optional<bt2c::Uuid> uuidOfObj(const bt2c::JsonObjVal& jsonObjVal)
{
    const auto jsonUuidVal = jsonObjVal[json_strings::uuid];

    if (!jsonUuidVal) {
        return nonstd::nullopt;
    }

    std::array<bt2c::Uuid::Val, bt2c::Uuid::size()> uuid;
    auto& jsonArrayUuidVal = jsonUuidVal->asArray();

    std::transform(jsonArrayUuidVal.begin(), jsonArrayUuidVal.end(), uuid.begin(),
                   [](const bt2c::JsonVal::UP& jsonUuidElemVal) {
                       return static_cast<bt2c::Uuid::Val>(*jsonUuidElemVal->asUInt());
                   });

    return bt2c::Uuid {uuid.data()};
}

} // namespace

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
                                            this->_locStr(jsonFragmentObj).c_str());
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
            this->_locStr(jsonFragmentObj).c_str());
    } else if (type == strings::fcAlias) {
        this->_handleFcAliasFragment(std::move(jsonFragment));
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

void Ctf2MetadataStreamParser::_validateScopeFcRoles(const Fc& fc,
                                                     const ir::UIntFieldRoles& allowedRoles,
                                                     const bool allowMetadataStreamUuidRole)
{
    validateScopeFcRoles(fc, allowedRoles, allowMetadataStreamUuidRole, this->_logCfg(),
                         this->_textLocStrFmt());
}

void Ctf2MetadataStreamParser::_validatePktHeaderFcRoles(const Fc& pktHeaderFc)
{
    /* Validate allowed roles */
    this->_validateScopeFcRoles(pktHeaderFc,
                                {ir::UIntFieldRole::PKT_MAGIC_NUMBER,
                                 ir::UIntFieldRole::DATA_STREAM_CLS_ID,
                                 ir::UIntFieldRole::DATA_STREAM_ID},
                                true);

    /*
     * Validate that, if an unsigned integer field class has a "packet
     * magic number" role:
     *
     * • FC is a 32-bit fixed-length unsigned integer field class.
     *
     * • FC is the field class of the first member class of the packet
     *   header scope structure field class.
     *
     * • There's only one such field class within the whole packet
     *   header scope field class.
     */
    {
        const auto fcs = fcsWithRole(pktHeaderFc, {ir::UIntFieldRole::PKT_MAGIC_NUMBER}, false);

        if (fcs.size() > 1) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error,
                "[%s] Packet header field class may contain zero or one field class having the role `%s`, not %zu.",
                this->_locStr(**fcs.begin()).c_str(), strings::pktMagicNumber, fcs.size());
        }

        if (!fcs.empty()) {
            auto& magicFc = **fcs.begin();

            if (&pktHeaderFc.asStruct()[0].fc() != &magicFc) {
                BT_CLOGE_APPEND_CAUSE_AND_THROW(
                    bt2c::Error,
                    "[%s] A field class having the `%s` role must be the first class of the first member class "
                    "of the packet header field class.",
                    this->_locStr(magicFc).c_str(), strings::pktMagicNumber);
            }

            if (!magicFc.isFixedLenUInt()) {
                BT_CLOGE_APPEND_CAUSE_AND_THROW(
                    bt2c::Error,
                    "[%s] Unexpected type of field class having the `%s` role: "
                    "expecting `%s` or `%s`.",
                    this->_locStr(magicFc).c_str(), strings::pktMagicNumber, strings::fixedLenUInt,
                    strings::fixedLenUEnum);
            }

            auto& magicUIntFc = magicFc.asFixedLenUInt();

            if (*magicUIntFc.len() != 32) {
                BT_CLOGE_APPEND_CAUSE_AND_THROW(
                    bt2c::Error,
                    "[%s] Unexpected `%s` property of fixed-length unsigned integer field class having the `%s` role: "
                    "expecting 32, not %llu.",
                    this->_locStr(magicFc).c_str(), strings::len, strings::pktMagicNumber,
                    *magicUIntFc.len());
            }
        }
    }

    /*
     * Validate that, if there's at least one static-length BLOB field
     * class having the "metadata stream UUID" role, then the metadata
     * stream has a UUID.
     */
    {
        const auto fcs = fcsWithRole(pktHeaderFc, {}, true);

        if (!fcs.empty() && !_mMetadataStreamUuid) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error,
                "[%s] Static-length BLOB field class has the role `%s`, "
                "but the preamble fragment of the metadata stream has no `%s` property.",
                this->_locStr(**fcs.begin()).c_str(), strings::metadataStreamUuid, strings::uuid);
        }
    }
}

void Ctf2MetadataStreamParser::_handleFcAliasFragment(bt2c::JsonVal::UP jsonFragment)
{
    auto& jsonFragmentObj = jsonFragment->asObj();
    auto& jsonNameVal = jsonFragmentObj[strings::name]->asStr();

    try {
        _mFcBuilder.addFcAlias(*jsonNameVal,
                               _mFcBuilder.buildFcFromJsonVal(*jsonFragmentObj[strings::fc]),
                               jsonNameVal.loc());
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid field class alias fragment.",
                                          this->_locStr(jsonFragmentObj).c_str());
    }
}

void Ctf2MetadataStreamParser::_handleTraceClsFragment(bt2c::JsonVal::UP jsonFragment)
{
    auto& jsonFragmentObj = jsonFragment->asObj();

    /* Check for trace class uniqueness */
    if (_mTraceCls) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "[%s] Duplicate trace class fragment.",
                                        this->_locStr(jsonFragmentObj).c_str());
    }

    /* Create the packet header field class and validate it */
    auto pktHeaderFc = this->_scopeFcOfJsonVal(jsonFragmentObj, strings::pktHeaderFc,
                                               ir::FieldLocScope::PKT_HEADER);

    if (pktHeaderFc) {
        try {
            this->_validatePktHeaderFcRoles(*pktHeaderFc);
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid packet header field class.",
                                              this->_locStr(*pktHeaderFc).c_str());
        }
    }

    /* Create the trace class */
    _mTraceCls = createTraceCls(optStrOfObj(jsonFragmentObj, strings::uid),
                                bt2ValueOfObj(jsonFragmentObj, strings::env),
                                std::move(pktHeaderFc), userAttrsOfObj(jsonFragmentObj));
}

namespace {

nonstd::optional<std::pair<std::string, bt2c::TextLoc>>
optStrOfObjWithLoc(const bt2c::JsonObjVal& jsonObjVal, const std::string& propName)
{
    if (const auto jsonVal = jsonObjVal[propName]) {
        return std::make_pair(*jsonVal->asStr(), jsonVal->loc());
    }

    return nonstd::nullopt;
}

} /* namespace */

void Ctf2MetadataStreamParser::_handleClkClsFragment(const bt2c::JsonObjVal& jsonFragment)
{
    /* Name */
    const auto name = jsonFragment.rawStrVal(strings::name);

    if (bt2c::contains(_mClkClasses, name)) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                        "[%s] Duplicate clock class fragment named `%s`.",
                                        this->_locStr(jsonFragment).c_str(), name.c_str());
    }

    /* Description */
    const auto descr = optStrOfObj(jsonFragment, strings::descr);

    /* Offset from origin */
    auto& jsonOffsetVal = jsonFragment.val(strings::offsetFromOrigin, *_mDefClkOffsetVal);
    const auto jsonOffsetSecsVal = jsonOffsetVal[strings::seconds];
    auto offsetSecs = 0LL;

    if (jsonOffsetSecsVal) {
        offsetSecs = rawIntValFromJsonIntVal<long long>(*jsonOffsetSecsVal);
    }

    const auto offsetCycles = jsonOffsetVal.rawVal(strings::cycles, 0ULL);

    /* Origin */
    nonstd::optional<ir::ClkOrigin> origin;

    if (const auto jsonOriginVal = jsonFragment[strings::origin]) {
        if (jsonOriginVal->isStr()) {
            /* Unix epoch */
            BT_ASSERT(*jsonOriginVal->asStr() == strings::unixEpoch);
            origin.emplace();
        } else {
            /* Defined by the producer */
            auto& jsonOriginObjVal = jsonOriginVal->asObj();

            /* Namespace */
            auto ns = optStrOfObj(jsonOriginObjVal, strings::ns);

            /* Create clock origin */
            origin.emplace(std::move(ns), *jsonOriginObjVal[strings::name]->asStr(),
                           *jsonOriginObjVal[strings::uid]->asStr());
        }
    }

    /* Create corresponding clock class */
    auto clkCls =
        createClkCls(name, jsonFragment.rawUIntVal(strings::freq),
                     ir::ClkOffset {offsetSecs, offsetCycles}, std::move(origin), std::move(descr),
                     jsonFragment.rawVal(strings::precision, 0ULL), userAttrsOfObj(jsonFragment));

    /* Add to map of clock classes */
    _mClkClasses.emplace(std::make_pair(std::move(name), std::move(clkCls)));
}

namespace {

std::string fullClsId(const unsigned long long id, const nonstd::optional<std::string>& ns,
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

} /* namespace */

void Ctf2MetadataStreamParser::_validateClkTsRoles(const Fc& fc, const bool allowClkTsRole)
{
    const auto fcs = fcsWithRole(
        fc, {ir::UIntFieldRole::DEF_CLK_TS, ir::UIntFieldRole::PKT_END_DEF_CLK_TS}, false);

    if (!fcs.empty() && !allowClkTsRole) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(
            bt2c::Error,
            "[%s] Invalid unsigned integer field class having the `%s` or `%s` role because its containing data stream class fragment has no default clock class (missing `%s` property).",
            this->_locStr(**fcs.begin()).c_str(), strings::defClkTs, strings::pktEndDefClkTs,
            strings::defClkClsName);
    }
}

void Ctf2MetadataStreamParser::_validateDataStreamClsRoles(const Fc * const pktCtxFc,
                                                           const Fc * const eventRecordHeaderFc,
                                                           const Fc * const commonEventRecordCtxFc,
                                                           const bool allowClkTsRole)
{
    if (pktCtxFc) {
        try {
            this->_validateScopeFcRoles(
                *pktCtxFc,
                {ir::UIntFieldRole::PKT_TOTAL_LEN, ir::UIntFieldRole::PKT_CONTENT_LEN,
                 ir::UIntFieldRole::DEF_CLK_TS, ir::UIntFieldRole::PKT_END_DEF_CLK_TS,
                 ir::UIntFieldRole::DISC_EVENT_RECORD_COUNTER_SNAP, ir::UIntFieldRole::PKT_SEQ_NUM},
                false);
            this->_validateClkTsRoles(*pktCtxFc, allowClkTsRole);
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid packet context field class.",
                                              this->_locStr(*pktCtxFc).c_str());
        }
    }

    if (eventRecordHeaderFc) {
        try {
            this->_validateScopeFcRoles(
                *eventRecordHeaderFc,
                {ir::UIntFieldRole::DEF_CLK_TS, ir::UIntFieldRole::EVENT_RECORD_CLS_ID}, false);
            this->_validateClkTsRoles(*eventRecordHeaderFc, allowClkTsRole);
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid event record header field class.",
                                              this->_locStr(*eventRecordHeaderFc).c_str());
        }
    }

    if (commonEventRecordCtxFc) {
        try {
            /* No roles allowed */
            this->_validateScopeFcRoles(*commonEventRecordCtxFc, {}, false);
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW(
                "[%s] Invalid common event record context field class.",
                this->_locStr(*commonEventRecordCtxFc).c_str());
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
                                        this->_locStr(jsonFragmentObj).c_str(), id);
    }

    /* Default clock class name */
    ClkCls::SP defClkCls;

    if (const auto defClkClsName = optStrOfObjWithLoc(jsonFragmentObj, strings::defClkClsName)) {
        const auto it = _mClkClasses.find(defClkClsName->first);

        if (it == _mClkClasses.end()) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error, "[%s] `%s` doesn't name an existing clock class fragment.",
                this->_locStr(defClkClsName->second).c_str(), defClkClsName->first.c_str());
        }

        defClkCls = it->second;
    }

    /* Namespace and name */
    const auto ns = optStrOfObj(jsonFragmentObj, strings::ns);
    const auto name = optStrOfObj(jsonFragmentObj, strings::name);

    /* Create data stream class */
    try {
        /* Create field classes */
        auto pktCtxFc = this->_dataStreamClsScopeFcOfJsonVal(jsonFragmentObj, strings::pktCtxFc,
                                                             ir::FieldLocScope::PKT_CTX);
        auto eventRecordHeaderFc = this->_dataStreamClsScopeFcOfJsonVal(
            jsonFragmentObj, strings::eventRecordHeaderFc, ir::FieldLocScope::EVENT_RECORD_HEADER,
            pktCtxFc.get());
        auto commonEventRecordCtxFc = this->_dataStreamClsScopeFcOfJsonVal(
            jsonFragmentObj, strings::eventRecordCommonCtxFc,
            ir::FieldLocScope::EVENT_RECORD_COMMON_CTX, pktCtxFc.get(), eventRecordHeaderFc.get());

        /* Validate roles */
        this->_validateDataStreamClsRoles(pktCtxFc.get(), eventRecordHeaderFc.get(),
                                          commonEventRecordCtxFc.get(),
                                          static_cast<bool>(defClkCls));

        /* Create and add data stream class to current trace class */
        _mTraceCls->addDataStreamCls(
            createDataStreamCls(id, ns, name, std::move(pktCtxFc), std::move(eventRecordHeaderFc),
                                std::move(commonEventRecordCtxFc), std::move(defClkCls),
                                userAttrsOfObj(jsonFragmentObj)));
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid data stream class fragment %s.",
                                          this->_locStr(jsonFragmentObj).c_str(),
                                          fullClsId(id, ns, name).c_str());
    }
}

void Ctf2MetadataStreamParser::_validateEventRecordClsRoles(const Fc * const specCtxFc,
                                                            const Fc * const payloadFc)
{
    if (specCtxFc) {
        try {
            /* No roles allowed */
            this->_validateScopeFcRoles(*specCtxFc, {}, false);
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid specific context field class.",
                                              this->_locStr(*specCtxFc).c_str());
        }
    }

    if (payloadFc) {
        try {
            /* No roles allowed */
            this->_validateScopeFcRoles(*payloadFc, {}, false);
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid payload field class.",
                                              this->_locStr(*payloadFc).c_str());
        }
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
            this->_locStr(jsonDataStreamClsIdVal ? *jsonDataStreamClsIdVal : jsonFragment).c_str(),
            dataStreamClsId);
    }

    /* ID */
    const auto jsonIdVal = jsonFragment[strings::id];
    const auto id = jsonIdVal ? *jsonIdVal->asUInt() : 0ULL;

    if ((*dataStreamCls)[id]) {
        BT_CLOGE_APPEND_CAUSE_AND_THROW(
            bt2c::Error,
            "[%s] Duplicate event record class fragment with ID %llu within data stream class fragment %s.",
            this->_locStr(jsonIdVal ? *jsonIdVal : jsonFragment).c_str(), id,
            fullClsId(*dataStreamCls).c_str());
    }

    /* Create event record class */
    const auto ns = optStrOfObj(jsonFragment, strings::ns);
    const auto name = optStrOfObj(jsonFragment, strings::name);

    try {
        /* Create field classes */
        auto specCtxFc = this->_eventRecordClsScopeFcOfJsonVal(
            jsonFragment, strings::specCtxFc, ir::FieldLocScope::EVENT_RECORD_SPEC_CTX,
            *dataStreamCls);
        auto payloadFc = this->_eventRecordClsScopeFcOfJsonVal(
            jsonFragment, strings::payloadFc, ir::FieldLocScope::EVENT_RECORD_PAYLOAD,
            *dataStreamCls, specCtxFc.get());

        /* Validate roles */
        this->_validateEventRecordClsRoles(specCtxFc.get(), payloadFc.get());

        /* Create and add event record class to data stream class */
        dataStreamCls->addEventRecordCls(createEventRecordCls(id, ns, name, std::move(specCtxFc),
                                                              std::move(payloadFc),
                                                              userAttrsOfObj(jsonFragment)));
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW(
            "[%s] Invalid event record class fragment %s (for data stream class fragment %s).",
            this->_locStr(jsonFragment).c_str(), fullClsId(id, ns, name).c_str(),
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

Fc::UP Ctf2MetadataStreamParser::_scopeFcOfJsonVal(
    const bt2c::JsonObjVal& jsonVal, const std::string& key, const ir::FieldLocScope scope,
    const Fc *pktHeaderFc, const Fc *pktCtxFc, const Fc *eventRecordHeaderFc,
    const Fc *commonEventRecordCtxFc, const Fc *specEventRecordCtxFc,
    const Fc *eventRecordPayloadFc)
{
    const auto jsonFcVal = jsonVal[key];

    if (!jsonFcVal) {
        return nullptr;
    }

    try {
        /* Build field class */
        auto fc = _mFcBuilder.buildFcFromJsonVal(jsonFcVal->asObj());

        /* Make sure it's a structure field class */
        if (!fc->isStruct()) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "[%s] Expecting a structure field class.",
                                            this->_locStr(*fc).c_str());
        }

        /* Normalize field locations (relative → absolute) */
        normalizeFieldLocs(*fc, scope, this->_logCfg(), this->_textLocStrFmt());

        /*
         * Resolve `OPTIONAL_WITH_UINT_SEL` and `VARIANT_WITH_UINT_SEL`
         * field classes.
         */
        switch (scope) {
        case ir::FieldLocScope::PKT_HEADER:
            pktHeaderFc = fc.get();
            break;
        case ir::FieldLocScope::PKT_CTX:
            pktCtxFc = fc.get();
            break;
        case ir::FieldLocScope::EVENT_RECORD_HEADER:
            eventRecordHeaderFc = fc.get();
            break;
        case ir::FieldLocScope::EVENT_RECORD_COMMON_CTX:
            commonEventRecordCtxFc = fc.get();
            break;
        case ir::FieldLocScope::EVENT_RECORD_SPEC_CTX:
            specEventRecordCtxFc = fc.get();
            break;
        case ir::FieldLocScope::EVENT_RECORD_PAYLOAD:
            eventRecordPayloadFc = fc.get();
            break;
        default:
            bt_common_abort();
        }

        resolveFcsWithIntSel(*fc, scope, pktHeaderFc, pktCtxFc, eventRecordHeaderFc,
                             commonEventRecordCtxFc, specEventRecordCtxFc, eventRecordPayloadFc,
                             this->_logCfg(), this->_textLocStrFmt());

        /* Done! */
        return fc;
    } catch (const bt2c::Error&) {
        BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid %s scope.", this->_locStr(jsonVal).c_str(),
                                          scopeStr(scope));
    }
}

Fc::UP Ctf2MetadataStreamParser::_eventRecordClsScopeFcOfJsonVal(
    const bt2c::JsonObjVal& jsonEventRecordCls, const std::string& key,
    const ir::FieldLocScope scope, const DataStreamCls& dataStreamCls,
    const Fc * const specEventRecordCtxFc, const Fc * const eventRecordPayloadFc)
{
    return this->_scopeFcOfJsonVal(jsonEventRecordCls, key, scope, _mTraceCls->pktHeaderFc(),
                                   dataStreamCls.pktCtxFc(), dataStreamCls.eventRecordHeaderFc(),
                                   dataStreamCls.commonEventRecordCtxFc(), specEventRecordCtxFc,
                                   eventRecordPayloadFc);
}

Fc::UP Ctf2MetadataStreamParser::_dataStreamClsScopeFcOfJsonVal(
    const bt2c::JsonObjVal& jsonDataStreamCls, const std::string& key,
    const ir::FieldLocScope scope, const Fc * const pktCtxFc, const Fc * const eventRecordHeaderFc,
    const Fc * const commonEventRecordCtxFc)
{
    return this->_scopeFcOfJsonVal(jsonDataStreamCls, key, scope, _mTraceCls->pktHeaderFc(),
                                   pktCtxFc, eventRecordHeaderFc, commonEventRecordCtxFc);
}

} /* namespace src */
} /* namespace ctf */
