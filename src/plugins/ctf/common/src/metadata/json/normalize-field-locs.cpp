/*
 * Copyright (c) 2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#define BT_LOG_TAG  "PLUGIN/CTF/CTF-2-NORMALIZE-FIELD-LOCS"
#define BT_CLOG_CFG this->_logCfg()
#include "cpp-common/cfg-logging-error-reporting-throw.hpp"

#include "common/common.h"
#include "common/assert.h"
#include "cpp-common/log-cfg.hpp"
#include "cpp-common/text-loc-str.hpp"
#include "utils.hpp"
#include "normalize-field-locs.hpp"
#include "logging-obj.hpp"

namespace ctf {
namespace src {

namespace bt2c = bt2_common;

namespace {

/*
 * Helper of normalizeFieldLocs().
 */
class Normalizer final : public FcVisitor, public LoggingObj
{
public:
    explicit Normalizer(const ir::FieldLocScope scope, const bt2c::LogCfg& logCfg,
                        const bt2c::TextLocStrFmt textLocStrFmt) :
        LoggingObj {logCfg, textLocStrFmt},
        _mScope {scope}
    {
    }

private:
    void visit(StaticLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(DynLenArrayFc& fc) override
    {
        fc.lenFieldLoc(this->_normalizeFieldLoc(fc.lenFieldLoc()));
        this->_visit(fc);
    }

    void visit(StructFc& fc) override
    {
        for (auto& memberCls : fc) {
            _mMemberNames.push_back(&memberCls.name());

            try {
                memberCls.fc().accept(*this);
            } catch (const bt2c::Error&) {
                BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid structure field member class.",
                                                  this->_locStr(memberCls.fc()).c_str());
            }

            _mMemberNames.pop_back();
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
        /* Doesn't exist at this point */
        bt_common_abort();
    }

    void visit(VariantWithUIntSelFc& fc) override
    {
        fc.selFieldLoc(this->_normalizeFieldLoc(fc.selFieldLoc()));

        for (auto& opt : fc) {
            try {
                opt.fc().accept(*this);
            } catch (const bt2c::Error&) {
                BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid variant field class option.",
                                                  this->_locStr(opt.fc()).c_str());
            }
        }
    }

    void visit(VariantWithSIntSelFc& fc) override
    {
        /* Doesn't exist at this point */
        bt_common_abort();
    }

    void _visit(ArrayFc& fc)
    {
        try {
            fc.elemFc().accept(*this);
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW(
                "[%s] Invalid element field class of array field class.",
                this->_locStr(fc).c_str());
        }
    }

    void _visit(OptionalFc& fc)
    {
        fc.selFieldLoc(this->_normalizeFieldLoc(fc.selFieldLoc()));

        try {
            fc.fc().accept(*this);
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid field class of optional field class.",
                                              this->_locStr(fc).c_str());
        }
    }

    /*
     * Returns the normalized version of `fieldLoc`.
     */
    FieldLoc _normalizeFieldLoc(const FieldLoc& fieldLoc) const
    {
        if (fieldLoc.scope()) {
            /* Already absolute */
            return fieldLoc;
        }

        /*
         * First remove non-leading "parent" field location items.
         *
         * For example (using a file system notation):
         *
         * • `../../meow/mix/../glue/all` → `../../meow/glue/all`.
         * • `hello/../../world` → `../world`.
         */
        const auto tmpItems = [&fieldLoc] {
            FieldLoc::Items retItems;

            for (auto& item : fieldLoc.items()) {
                if (retItems.empty()) {
                    retItems.push_back(item);
                } else {
                    if (item) {
                        retItems.push_back(item);
                    } else {
                        /* Go back to known parent */
                        retItems.pop_back();
                    }
                }
            }

            return retItems;
        }();

        /*
         * Create absolute field location items.
         *
         * Example 1: with leading "parent" items
         * --------------------------------------
         * Given the temporary items `../meow/mix` and the current
         * member names `/red/blue/green` (`green` being the name of the
         * dependent field class having the location `fieldLoc`), then
         * after the loop below:
         *
         *     /red/blue/green
         *          ▲
         *          memberNameEndIt
         *
         *     ../meow/mix
         *        ▲
         *        tmpItemIt
         *
         * Final, absolute items:
         *
         *     /red/meow/mix
         *
         * Example 2: without leading "parent" items
         * -----------------------------------------
         * Given the temporary items `meow/mix` and the current member
         * names `/red/blue/green` (`green` being the name of the
         * dependent field class having the location `fieldLoc`), then
         * after the loop below:
         *
         *     /red/blue/green
         *               ▲
         *               memberNameEndIt
         *
         *     meow/mix
         *     ▲
         *     tmpItemIt
         *
         * Final, absolute items:
         *
         *     /red/blue/meow/mix
         */
        BT_ASSERT(!_mMemberNames.empty());

        auto memberNameEndIt = _mMemberNames.end() - 1;
        auto tmpItemIt = tmpItems.begin();

        for (; tmpItemIt != tmpItems.end(); ++tmpItemIt) {
            if (*tmpItemIt) {
                /* End of leading "parent" items */
                break;
            }

            if (memberNameEndIt == _mMemberNames.begin()) {
                BT_CLOGE_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, "[%s] Invalid field location: too many \"parent\" path items.",
                    this->_locStr(fieldLoc.loc()).c_str());
            }

            --memberNameEndIt;
        }

        FieldLoc::Items items;

        for (auto memberNameIt = _mMemberNames.begin(); memberNameIt != memberNameEndIt;
             ++memberNameIt) {
            items.push_back(**memberNameIt);
        }

        for (; tmpItemIt != tmpItems.end(); ++tmpItemIt) {
            items.push_back(*tmpItemIt);
        }

        /* Create absolute field location */
        return createFieldLoc(_mScope, std::move(items), fieldLoc.loc());
    }

    std::vector<const std::string *> _mMemberNames;
    ir::FieldLocScope _mScope;
};

} /* namespace */

void normalizeFieldLocs(Fc& scopeFc, const ir::FieldLocScope scope, const bt2c::LogCfg& logCfg,
                        const bt2c::TextLocStrFmt textLocStrFmt)
{
    Normalizer normalizer {scope, logCfg, textLocStrFmt};

    scopeFc.accept(normalizer);
}

} /* namespace src */
} /* namespace ctf */
