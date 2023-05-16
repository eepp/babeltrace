/*
 * Copyright (c) 2022-2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#define BT_LOG_TAG  "PLUGIN/CTF/CTF-2-VALIDATE-SCOPE-FC-ROLES"
#define BT_CLOG_CFG this->_logCfg()
#include "cpp-common/cfg-logging-error-reporting-throw.hpp"

#include <sstream>

#include "cpp-common/contains.hpp"
#include "validate-scope-fc-roles.hpp"
#include "utils.hpp"
#include "../../../metadata/json/strings.hpp"
#include "logging-obj.hpp"

namespace ctf {
namespace src {

namespace bt2c = bt2_common;

namespace {

const char *validScopeNamesForRole(const ir::UIntFieldRole role) noexcept
{
    switch (role) {
    case ir::UIntFieldRole::PKT_MAGIC_NUMBER:
    case ir::UIntFieldRole::DATA_STREAM_CLS_ID:
    case ir::UIntFieldRole::DATA_STREAM_ID:
        return "a packet header";
    case ir::UIntFieldRole::DEF_CLK_TS:
        return "a packet context or an event record header";
    case ir::UIntFieldRole::PKT_TOTAL_LEN:
    case ir::UIntFieldRole::PKT_CONTENT_LEN:
    case ir::UIntFieldRole::PKT_END_DEF_CLK_TS:
    case ir::UIntFieldRole::DISC_EVENT_RECORD_COUNTER_SNAP:
    case ir::UIntFieldRole::PKT_SEQ_NUM:
        return "a packet context";
    case ir::UIntFieldRole::EVENT_RECORD_CLS_ID:
        return "an event record header";
    default:
        bt_common_abort();
    }
}

static inline const char *uIntFcRoleJsonStr(const ir::UIntFieldRole role) noexcept
{
    switch (role) {
    case ir::UIntFieldRole::PKT_MAGIC_NUMBER:
        return json_strings::pktMagicNumber;
    case ir::UIntFieldRole::DATA_STREAM_CLS_ID:
        return json_strings::dataStreamClsId;
    case ir::UIntFieldRole::DATA_STREAM_ID:
        return json_strings::dataStreamId;
    case ir::UIntFieldRole::PKT_TOTAL_LEN:
        return json_strings::pktTotalLen;
    case ir::UIntFieldRole::PKT_CONTENT_LEN:
        return json_strings::pktContentLen;
    case ir::UIntFieldRole::DEF_CLK_TS:
        return json_strings::defClkTs;
    case ir::UIntFieldRole::PKT_END_DEF_CLK_TS:
        return json_strings::pktEndDefClkTs;
    case ir::UIntFieldRole::DISC_EVENT_RECORD_COUNTER_SNAP:
        return json_strings::discEventRecordCounterSnap;
    case ir::UIntFieldRole::PKT_SEQ_NUM:
        return json_strings::pktSeqNum;
    case ir::UIntFieldRole::EVENT_RECORD_CLS_ID:
        return json_strings::eventRecordClsId;
    default:
        bt_common_abort();
    }
}

/*
 * Helper of validateScopeFcRoles().
 */
class Validator final : public ConstFcVisitor, public LoggingObj
{
public:
    explicit Validator(const ir::UIntFieldRoles& allowedRoles,
                       const bool allowMetadataStreamUuidRole, const bt2c::LogCfg& logCfg,
                       const bt2c::TextLocStrFmt textLocStrFmt) :
        LoggingObj {logCfg, textLocStrFmt},
        _mAllowedRoles {&allowedRoles}, _mAllowMetadataStreamUuidRole {allowMetadataStreamUuidRole}
    {
    }

private:
    void visit(const FixedLenUIntFc& fc) override
    {
        this->_validateUIntFc(fc);
    }

    void visit(const FixedLenUEnumFc& fc) override
    {
        this->_validateUIntFc(fc);
    }

    void visit(const VarLenUIntFc& fc) override
    {
        this->_validateUIntFc(fc);
    }

    void visit(const VarLenUEnumFc& fc) override
    {
        this->_validateUIntFc(fc);
    }

    void visit(const StaticLenBlobFc& fc) override
    {
        if (fc.asStaticLenBlob().hasMetadataStreamUuidRole() && !_mAllowMetadataStreamUuidRole) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2_common::Error,
                                            "[%s] Static-length BLOB field class may not have the "
                                            "`%s` role here "
                                            "(only valid within a packet header field class).",
                                            this->_locStr(fc).c_str(),
                                            json_strings::metadataStreamUuid);
        }
    }

    void visit(const StaticLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const DynLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const StructFc& fc) override
    {
        for (auto& memberCls : fc) {
            try {
                memberCls.fc().accept(*this);
            } catch (const bt2c::Error&) {
                BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid structure field member class.",
                                                  this->_locStr(memberCls.fc()).c_str());
            }
        }
    }

    void visit(const OptionalWithBoolSelFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const OptionalWithUIntSelFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const OptionalWithSIntSelFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const VariantWithUIntSelFc& fc) override
    {
        this->_visitVariantFc(fc);
    }

    void visit(const VariantWithSIntSelFc& fc) override
    {
        this->_visitVariantFc(fc);
    }

    template <typename UIntFcT>
    void _validateUIntFc(const UIntFcT& fc) const
    {
        for (const auto role : fc.roles()) {
            if (!bt2c::contains(*_mAllowedRoles, role)) {
                BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                                "[%s] Unsigned integer field class may not have "
                                                "the `%s` role here "
                                                "(only valid within %s field class).",
                                                this->_locStr(fc).c_str(), uIntFcRoleJsonStr(role),
                                                validScopeNamesForRole(role));
            }
        }
    }

    void _visit(const ArrayFc& fc)
    {
        try {
            fc.elemFc().accept(*this);
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW(
                "[%s] Invalid element field class of array field class.",
                this->_locStr(fc).c_str());
        }
    }

    void _visit(const OptionalFc& fc)
    {
        try {
            fc.fc().accept(*this);
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid field class of optional field class.",
                                              this->_locStr(fc).c_str());
        }
    }

    template <typename VarFcT>
    void _visitVariantFc(const VarFcT& fc)
    {
        for (auto& opt : fc) {
            try {
                opt.fc().accept(*this);
            } catch (const bt2c::Error&) {
                BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid variant field class option.",
                                                  this->_locStr(opt.fc()).c_str());
            }
        }
    }

    const ir::UIntFieldRoles *_mAllowedRoles;
    bool _mAllowMetadataStreamUuidRole;
};

} /* namespace */

void validateScopeFcRoles(const Fc& fc, const ir::UIntFieldRoles& allowedRoles,
                          const bool allowMetadataStreamUuidRole, const bt2c::LogCfg& logCfg,
                          const bt2c::TextLocStrFmt textLocStrFmt)
{
    Validator validator {allowedRoles, allowMetadataStreamUuidRole, logCfg, textLocStrFmt};

    fc.accept(validator);
}

} /* namespace src */
} /* namespace ctf */
