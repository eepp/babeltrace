/*
 * Copyright (c) 2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#define BT_LOG_TAG  "PLUGIN/CTF/CTF-2-RES-FCS-WITH-INT-SEL"
#define BT_CLOG_CFG this->_logCfg()
#include "cpp-common/cfg-logging-error-reporting-throw.hpp"

#include <unordered_set>
#include <unordered_map>
#include <utility>

#include "common/common.h"
#include "common/assert.h"
#include "cpp-common/log-cfg.hpp"
#include "cpp-common/text-loc-str.hpp"
#include "utils.hpp"
#include "resolve-fcs-with-int-sel.hpp"
#include "fc-dep-types.hpp"
#include "logging-obj.hpp"

namespace ctf {
namespace src {

namespace bt2c = bt2_common;

namespace {

SIntRangeSet sIntRangeSetFromUIntRangeSet(const UIntRangeSet& uIntRanges)
{
    SIntRangeSet::Set sIntRanges;

    for (auto& uIntRange : uIntRanges) {
        sIntRanges.insert(SIntRangeSet::Range {static_cast<SIntRangeSet::Val>(uIntRange.lower()),
                                               static_cast<SIntRangeSet::Val>(uIntRange.upper())});
    }

    return SIntRangeSet {std::move(sIntRanges)};
}

/*
 * Helper of resolveFcsWithIntSel().
 */
class Resolver final : public FcVisitor, public LoggingObj
{
public:
    explicit Resolver(const FcDepTypes& depTypes, const bt2c::LogCfg& logCfg,
                      const bt2c::TextLocStrFmt textLocStrFmt) :
        LoggingObj {logCfg, textLocStrFmt},
        _mDepTypes {&depTypes}
    {
    }

private:
    void visit(StaticLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(DynLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(StructFc& fc) override
    {
        for (auto& memberCls : fc) {
            try {
                memberCls.fc(this->_resolveFc(memberCls.takeFc()));
                memberCls.fc().accept(*this);
            } catch (const bt2c::Error&) {
                BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid structure field member class.",
                                                  this->_locStr(memberCls.fc()).c_str());
            }
        }
    }

    void visit(OptionalWithBoolSelFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(OptionalWithUIntSelFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(OptionalWithSIntSelFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(VariantWithUIntSelFc& fc) override
    {
        this->_visitVariantFc(fc);
    }

    void visit(VariantWithSIntSelFc& fc) override
    {
        this->_visitVariantFc(fc);
    }

    void _visit(ArrayFc& fc)
    {
        try {
            fc.elemFc(this->_resolveFc(fc.takeElemFc()));
            fc.elemFc().accept(*this);
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW(
                "[%s] Invalid element field class of array field class.",
                this->_locStr(fc).c_str());
        }
    }

    void _visit(OptionalFc& fc)
    {
        try {
            fc.fc(this->_resolveFc(fc.takeFc()));
            fc.fc().accept(*this);
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid field class of optional field class.",
                                              this->_locStr(fc).c_str());
        }
    }

    template <typename VarFcT>
    void _visitVariantFc(VarFcT& fc)
    {
        for (auto& opt : fc) {
            try {
                opt.fc(this->_resolveFc(opt.takeFc()));
                opt.fc().accept(*this);
            } catch (const bt2c::Error&) {
                BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid variant field class option.",
                                                  this->_locStr(opt.fc()).c_str());
            }
        }
    }

    Fc::UP _resolveFc(Fc::UP fc)
    {
        if (!fc->isOptionalWithUIntSel() && !fc->isVariantWithUIntSel()) {
            /* Not a candidate for replacement: return as is */
            return fc;
        }

        const auto depType = _mDepTypes->at(fc.get());

        if (depType == FcDepType::UINT) {
            /* Type of `*fc` is already correct: return as is */
            return fc;
        }

        BT_ASSERT(depType == FcDepType::SINT);

        /*
         * The goal here is to create an `OPTIONAL_WITH_SINT_SEL` or a
         * `VARIANT_WITH_SINT_SEL` field class from an
         * `OPTIONAL_WITH_UINT_SEL` or a `VARIANT_WITH_UINT_SEL` field
         * class, stealing (moving) as much as possible from `*fc` as it
         * will be discarded anyway (explaining all the take*() method
         * calls).
         *
         * sIntRangeSetFromUIntRangeSet() converts the selector field
         * ranges from unsigned to signed.
         */
        if (fc->isOptionalWithUIntSel()) {
            auto& optionalFc = fc->asOptionalWithUIntSel();

            return createOptionalFc(optionalFc.loc(), optionalFc.takeFc(),
                                    optionalFc.takeSelFieldLoc(),
                                    sIntRangeSetFromUIntRangeSet(optionalFc.selFieldRanges()),
                                    optionalFc.takeUserAttrs());
        } else {
            BT_ASSERT(fc->isVariantWithUIntSel());

            auto& varFc = fc->asVariantWithUIntSel();
            VariantWithSIntSelFc::Opts newOpts;

            for (auto& opt : varFc) {
                newOpts.emplace_back(createVariantFcOpt(
                    opt.takeFc(), sIntRangeSetFromUIntRangeSet(opt.selFieldRanges()),
                    opt.takeName(), opt.takeUserAttrs()));
            }

            return createVariantFc(varFc.loc(), std::move(newOpts), varFc.takeSelFieldLoc(),
                                   varFc.takeUserAttrs());
        }
    }

    const FcDepTypes *_mDepTypes;
};

} /* namespace */

void resolveFcsWithIntSel(Fc& scopeFc, const ir::FieldLocScope scope, const Fc * const pktHeaderFc,
                          const Fc * const pktCtxFc, const Fc * const eventRecordHeaderFc,
                          const Fc * const commonEventRecordCtxFc,
                          const Fc * const specEventRecordCtxFc,
                          const Fc * const eventRecordPayloadFc, const bt2c::LogCfg& logCfg,
                          const bt2c::TextLocStrFmt textLocStrFmt)
{
    const auto depTypes = fcDepTypes(scopeFc, scope, pktHeaderFc, pktCtxFc, eventRecordHeaderFc,
                                     commonEventRecordCtxFc, specEventRecordCtxFc,
                                     eventRecordPayloadFc, logCfg, textLocStrFmt);
    Resolver resolver {depTypes, logCfg, textLocStrFmt};

    scopeFc.accept(resolver);
}

} /* namespace src */
} /* namespace ctf */
