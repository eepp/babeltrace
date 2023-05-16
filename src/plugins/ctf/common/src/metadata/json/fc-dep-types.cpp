/*
 * Copyright (c) 2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#define BT_LOG_TAG  "PLUGIN/CTF/CTF-2-FC-DEP-TYPES"
#define BT_CLOG_CFG this->_logCfg()
#include "cpp-common/cfg-logging-error-reporting-throw.hpp"

#include <unordered_set>
#include <unordered_map>
#include <utility>

#include "common/common.h"
#include "common/assert.h"
#include "cpp-common/contains.hpp"
#include "cpp-common/log-cfg.hpp"
#include "cpp-common/text-loc-str.hpp"
#include "../../../metadata/json/strings.hpp"
#include "utils.hpp"
#include "fc-dep-types.hpp"
#include "logging-obj.hpp"

namespace ctf {
namespace src {

namespace bt2c = bt2_common;

namespace {

/*
 * Helper of fcDepTypes().
 */
class FcDepTypesFinder final : public ConstFcVisitor, public LoggingObj
{
private:
    /* Current scope field classes */
    struct _Ctx
    {
        const Fc *pktHeaderFc;
        const Fc *pktCtxFc;
        const Fc *eventRecordHeaderFc;
        const Fc *commonEventRecordCtxFc;
        const Fc *specEventRecordCtxFc;
        const Fc *eventRecordPayloadFc;
    };

    /* Set of const field classes */
    using _ConstFcSet = std::unordered_set<const Fc *>;

public:
    explicit FcDepTypesFinder(const ir::FieldLocScope scope, const Fc * const pktHeaderFc,
                              const Fc * const pktCtxFc, const Fc * const eventRecordHeaderFc,
                              const Fc * const commonEventRecordCtxFc,
                              const Fc * const specEventRecordCtxFc,
                              const Fc * const eventRecordPayloadFc, const bt2c::LogCfg& logCfg,
                              const bt2c::TextLocStrFmt textLocStrFmt) :
        LoggingObj {logCfg, textLocStrFmt},
        _mScope {scope}, _mCtx {pktHeaderFc,          pktCtxFc,
                                eventRecordHeaderFc,  commonEventRecordCtxFc,
                                specEventRecordCtxFc, eventRecordPayloadFc}
    {
    }

    /*
     * Moves the resulting field class dependency type map to the
     * caller.
     */
    FcDepTypes takeFcDepTypes() noexcept
    {
        return std::move(_mFcDepTypes);
    }

private:
    void visit(const StaticLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const DynLenArrayFc& fc) override
    {
        this->_addDynLenFcDepType(fc);
        this->_visit(fc);
    }

    void visit(const DynLenStrFc& fc) override
    {
        this->_addDynLenFcDepType(fc);
    }

    void visit(const DynLenBlobFc& fc) override
    {
        this->_addDynLenFcDepType(fc);
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
        /* Doesn't exist at this point */
        bt_common_abort();
    }

    void visit(const VariantWithUIntSelFc& fc) override
    {
        this->_addOptionalOrVariantFcDepType(fc);

        for (auto optIt = fc.begin(); optIt != fc.end(); ++optIt) {
            try {
                this->_withinCompoundFc(fc, optIt - fc.begin(), [this, &optIt] {
                    optIt->fc().accept(*this);
                });
            } catch (const bt2c::Error&) {
                BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid variant field class option.",
                                                  this->_locStr(optIt->fc()).c_str());
            }
        }
    }

    void visit(const VariantWithSIntSelFc& fc) override
    {
        /* Doesn't exist at this point */
        bt_common_abort();
    }

    void _visit(const ArrayFc& fc)
    {
        try {
            this->_withinCompoundFc(fc, [this, &fc] {
                fc.elemFc().accept(*this);
            });
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW(
                "[%s] Invalid element field class of array field class.",
                this->_locStr(fc).c_str());
        }
    }

    void _visit(const OptionalFc& fc)
    {
        const auto depType = this->_addOptionalOrVariantFcDepType(fc);

        if (fc.isOptionalWithBoolSel() && depType != FcDepType::BOOL) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error,
                "[%s] Expecting a class of optional fields with a boolean selector field "
                "because the `%s` property is absent.",
                this->_locStr(fc).c_str(), json_strings::selFieldRanges);
        }

        try {
            this->_withinCompoundFc(fc, [this, &fc] {
                fc.fc().accept(*this);
            });
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid field class of optional field class.",
                                              this->_locStr(fc).c_str());
        }
    }

    /*
     * Adds the dependency type of the dynamic-length field class `fc`
     * to `_mFcDepTypes`.
     */
    template <typename FcT>
    void _addDynLenFcDepType(FcT& fc)
    {
        this->_validateDynLenFcDepType(this->_addFcDeps(fc, fc.lenFieldLoc()), fc.lenFieldLoc());
    }

    /*
     * Adds the dependency type of the optional or variant field class
     * `fc` to `_mFcDepTypes` and returns said type.
     */
    template <typename FcT>
    FcDepType _addOptionalOrVariantFcDepType(FcT& fc)
    {
        return this->_depType(**this->_addFcDeps(fc, fc.selFieldLoc()).begin());
    }

    /*
     * Adds the dependency type of `fc` to `_mFcDepTypes` and returns
     * the dependencies of `fc`.
     */
    template <typename FcT>
    _ConstFcSet _addFcDeps(FcT& fc, const FieldLoc& fieldLoc)
    {
        auto deps = this->_findDeps(fc, fieldLoc);

        _mFcDepTypes.emplace(std::make_pair(&fc, this->_depType(**deps.begin())));
        return deps;
    }

    /*
     * Adds to `deps` the dependencies of `dependentFc`, using the field
     * location `fieldLoc`, from `baseFc` and the field location item
     * iterator `fieldLocIt`.
     *
     * Returns `true` if `dependentFc` isn't reached yet (safe to
     * continue to find dependencies).
     */
    bool _findDeps(const Fc& baseFc, const Fc& dependentFc, const FieldLoc& fieldLoc,
                   const FieldLoc::Items::const_iterator fieldLocIt, _ConstFcSet& deps) const
    {
        if (baseFc.isFixedLenBool() || baseFc.isInt()) {
            if (fieldLocIt != fieldLoc.end()) {
                BT_CLOGE_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, "[%s] Cannot reach anything beyond a scalar field class for %s.",
                    this->_locStr(baseFc).c_str(),
                    absFieldLocStr(fieldLoc, fieldLocIt + 1).c_str());
            }

            deps.insert(&baseFc);
            return true;
        } else if (baseFc.isStruct()) {
            if (fieldLocIt == fieldLoc.end()) {
                BT_CLOGE_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, "[%s] Field location must not locate a structure field class.",
                    this->_locStr(baseFc).c_str());
            }

            /* Find the member class named `**fieldLocIt` */
            for (auto& memberCls : baseFc.asStruct()) {
                if (&memberCls.fc() == &dependentFc) {
                    /* Reached the dependent field class */
                    return false;
                }

                if (memberCls.name() != **fieldLocIt) {
                    continue;
                }

                return this->_findDeps(memberCls.fc(), dependentFc, fieldLoc, fieldLocIt + 1, deps);
            }

            /* Member class not found */
            BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                            "[%s] At field location %s: "
                                            "no structure field member class named `%s`.",
                                            this->_locStr(baseFc).c_str(),
                                            absFieldLocStr(fieldLoc, fieldLocIt).c_str(),
                                            (*fieldLocIt)->c_str());
        } else if (baseFc.isArray()) {
            if (!bt2c::contains(_mCompoundFcIndexes, &baseFc)) {
                BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                                "[%s] At field location %s: "
                                                "unreachable array field element.",
                                                this->_locStr(baseFc).c_str(),
                                                absFieldLocStr(fieldLoc, fieldLocIt).c_str());
            }

            auto& elemFc = baseFc.asArray().elemFc();

            if (&elemFc == &dependentFc) {
                /* Reached the dependent field class */
                return false;
            }

            return this->_findDeps(elemFc, dependentFc, fieldLoc, fieldLocIt, deps);
        } else if (baseFc.isOptional()) {
            if (!bt2c::contains(_mCompoundFcIndexes, &baseFc)) {
                BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                                "[%s] At field location %s: "
                                                "unreachable optional field.",
                                                this->_locStr(baseFc).c_str(),
                                                absFieldLocStr(fieldLoc, fieldLocIt).c_str());
            }

            auto& optionalFc = baseFc.asOptional().fc();

            if (&optionalFc == &dependentFc) {
                /* Reached the dependent field class */
                return false;
            }

            return this->_findDeps(optionalFc, dependentFc, fieldLoc, fieldLocIt, deps);
        } else if (baseFc.isVariant()) {
            auto& opts = baseFc.asVariantWithUIntSel().opts();
            const auto curOptIndexIt = _mCompoundFcIndexes.find(&baseFc);

            if (curOptIndexIt == _mCompoundFcIndexes.end()) {
                /*
                 * Not currently visiting this variant field class:
                 * consider all options.
                 */
                for (auto& opt : opts) {
                    if (&opt.fc() == &dependentFc) {
                        /* Reached the dependent field class */
                        return false;
                    }

                    if (!this->_findDeps(opt.fc(), dependentFc, fieldLoc, fieldLocIt, deps)) {
                        /* Reached the dependent field class */
                        return false;
                    }
                }
            } else {
                /*
                 * Currently visiting this variant field class: consider
                 * only the currently visited option.
                 */
                auto& optFc = opts[curOptIndexIt->second].fc();

                if (&optFc == &dependentFc) {
                    /* Reached the dependent field class */
                    return false;
                }

                return this->_findDeps(optFc, dependentFc, fieldLoc, fieldLocIt, deps);
            }

            return true;
        } else {
            BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                            "[%s] At field location %s: "
                                            "unexpected type of field class.",
                                            this->_locStr(baseFc).c_str(),
                                            absFieldLocStr(fieldLoc, fieldLocIt).c_str());
        }
    }

    /*
     * Returns the dependency type from the type of `fc`.
     */
    static FcDepType _depType(const Fc& fc) noexcept
    {
        if (fc.isFixedLenBool()) {
            return FcDepType::BOOL;
        } else if (fc.isUInt()) {
            return FcDepType::UINT;
        } else {
            BT_ASSERT(fc.isSInt());
            return FcDepType::SINT;
        }
    };

    /*
     * Returns the field class (within `_mCtx`) of the scope of
     * `fieldLoc`.
     */
    const Fc& _scopeFc(const FieldLoc& fieldLoc) const
    {
        /* Validate the scope first */
        if (static_cast<int>(*fieldLoc.scope()) > static_cast<int>(_mScope)) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error,
                "[%s] A field within a %s field cannot depend on another field within a %s field (unreachable).",
                this->_locStr(fieldLoc.loc()).c_str(), scopeStr(_mScope),
                scopeStr(*fieldLoc.scope()));
        }

        /* Retrieve scope field class from `_mCtx` */
        const auto scopeFc = [this, &fieldLoc] {
            switch (*fieldLoc.scope()) {
            case ir::FieldLocScope::PKT_HEADER:
                return _mCtx.pktHeaderFc;
            case ir::FieldLocScope::PKT_CTX:
                return _mCtx.pktCtxFc;
            case ir::FieldLocScope::EVENT_RECORD_HEADER:
                return _mCtx.eventRecordHeaderFc;
            case ir::FieldLocScope::EVENT_RECORD_COMMON_CTX:
                return _mCtx.commonEventRecordCtxFc;
            case ir::FieldLocScope::EVENT_RECORD_SPEC_CTX:
                return _mCtx.specEventRecordCtxFc;
            case ir::FieldLocScope::EVENT_RECORD_PAYLOAD:
                return _mCtx.eventRecordPayloadFc;
            default:
                bt_common_abort();
            }
        }();

        if (!scopeFc) {
            BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "[%s] Missing required %s field class.",
                                            this->_locStr(fieldLoc.loc()).c_str(),
                                            scopeStr(*fieldLoc.scope()));
        }

        return *scopeFc;
    }

    /*
     * Finds the dependencies of `dependentFc` using the field location
     * `fieldLoc`.
     *
     * This method only considers boolean and integer field classes as
     * dependencies, throwing `bt2c::Error` when it finds anything else.
     *
     * This method doesn't add to the returned set field classes which
     * occur after `dependentFc` .
     *
     * This method also throws if:
     *
     * • `fieldLoc` is invalid anyhow.
     *
     * • `fieldLoc` locates field classes having different dependency
     *   types.
     *
     * • `fieldLoc` doesn't locate any field class.
     */
    _ConstFcSet _findDeps(const Fc& dependentFc, const FieldLoc& fieldLoc) const
    {
        try {
            /* Find dependencies and returns them */
            _ConstFcSet deps;

            this->_findDeps(this->_scopeFc(fieldLoc), dependentFc, fieldLoc, fieldLoc.begin(),
                            deps);

            /* Validate that `deps` contains at least one item */
            if (deps.empty()) {
                BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                                "[%s] Field location doesn't locate anything.",
                                                this->_locStr(fieldLoc.loc()).c_str());
            }

            /*
             * Validate that all the items of `deps` have the same type.
             */
            {
                const auto expectedType = this->_depType(**deps.begin());

                for (const auto fc : deps) {
                    if (this->_depType(*fc) != expectedType) {
                        BT_CLOGE_APPEND_CAUSE_AND_THROW(
                            bt2c::Error,
                            "[%s] Field location locates field classes having different types "
                            "([%s] and [%s]).",
                            this->_locStr(fieldLoc.loc()).c_str(),
                            this->_locStr(**deps.begin()).c_str(), this->_locStr(*fc).c_str());
                    }
                }
            }

            /* Return the set */
            return deps;
        } catch (const bt2c::Error&) {
            BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid field location %s.",
                                              this->_locStr(fieldLoc.loc()).c_str(),
                                              absFieldLocStr(fieldLoc, fieldLoc.end()).c_str());
        }
    }

    /*
     * Validates the dependency type `depType` for some dynamic-length
     * field class.
     */
    void _validateDynLenFcDepType(const _ConstFcSet& deps, const FieldLoc& fieldLoc) const
    {
        BT_ASSERT(!deps.empty());

        if (this->_depType(**deps.begin()) != FcDepType::UINT) {
            try {
                BT_CLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                                "[%s] Expecting an unsigned integer field class.",
                                                this->_locStr(**deps.begin()).c_str());
            } catch (const bt2c::Error&) {
                BT_CLOGE_APPEND_CAUSE_AND_RETHROW("[%s] Invalid field location %s.",
                                                  this->_locStr(fieldLoc.loc()).c_str(),
                                                  absFieldLocStr(fieldLoc, fieldLoc.end()).c_str());
            }
        }
    }

    /*
     * In this order:
     *
     * 1. Marks the underlying field class at the index `index` of the
     *    compound field class `fc` as being currently visited.
     *
     * 2. Calls `func()`.
     *
     * 3. Cancels 1.
     */
    template <typename FuncT>
    void _withinCompoundFc(const Fc& fc, const std::size_t index, FuncT&& func)
    {
        BT_ASSERT(!bt2c::contains(_mCompoundFcIndexes, &fc));
        _mCompoundFcIndexes.emplace(std::make_pair(&fc, index));
        func();
        _mCompoundFcIndexes.erase(&fc);
    }

    /*
     * In this order:
     *
     * 1. Marks the compound field class `fc` as being currently
     *    visited.
     *
     * 2. Calls `func()`.
     *
     * 3. Cancels 1.
     */
    template <typename FuncT>
    void _withinCompoundFc(const Fc& fc, FuncT&& func)
    {
        this->_withinCompoundFc(fc, 0, std::forward<FuncT>(func));
    }

    ir::FieldLocScope _mScope;
    _Ctx _mCtx;

    /* Result */
    FcDepTypes _mFcDepTypes;

    /*
     * Map of compound field classes to the index of the currently
     * visited immediate underlying field class, that is:
     *
     * For a variant field class F:
     *     Index of the option of F containing the field class currently
     *     being visited.
     *
     * For an array field class F:
     * For an optional field class F:
     *     0: if F is part of the map, then its element/optional field
     *     class is currently being visited.
     *
     * This is used to provide a visiting context to _findDeps() so as
     * to follow the correct variant field class option as
     * well as to validate dependencies.
     *
     * For example:
     *
     *     Root: Structure FC                                       [0]
     *       `len`: Fixed-length unsigned integer FC                [1]
     *       `meow`: Dynamic-length array FC                        [2]
     *         Element FC: Structure FC                             [3]
     *           `tag`: Fixed-length signed integer FC              [4]
     *           `val`: Variant FC                                  [5]
     *             `boss`: Null-terminated string FC                [6]
     *             `zoom`: Structure FC                             [7]
     *               `len`: Variable-length unsigned integer FC     [8]
     *               `data`: Dynamic-length BLOB FC                 [9]
     *             `line6`: Structure FC                            [10]
     *               `len`: Fixed-length unsigned integer FC        [11]
     *
     * If _findDeps() is currently visiting [9] to find its
     * dependencies, then the map would contain:
     *
     *     [2] → 0     (visiting current element of `/meow`)
     *     [5] → 1     (visiting second option (`zoom`) of `/meow/val`)
     *
     * This means that, if the length field location of [9] is
     * `/meow/val/len`, then we must only consider the `zoom` option,
     * not the `line6` one, even though both contain a member class
     * named `len`.
     */
    std::unordered_map<const Fc *, std::size_t> _mCompoundFcIndexes;
};

} /* namespace */

FcDepTypes fcDepTypes(const Fc& scopeFc, const ir::FieldLocScope scope,
                      const Fc * const pktHeaderFc, const Fc * const pktCtxFc,
                      const Fc * const eventRecordHeaderFc, const Fc * const commonEventRecordCtxFc,
                      const Fc * const specEventRecordCtxFc, const Fc * const eventRecordPayloadFc,
                      const bt2_common::LogCfg& logCfg, bt2_common::TextLocStrFmt textLocStrFmt)
{
    FcDepTypesFinder finder {scope,
                             pktHeaderFc,
                             pktCtxFc,
                             eventRecordHeaderFc,
                             commonEventRecordCtxFc,
                             specEventRecordCtxFc,
                             eventRecordPayloadFc,
                             logCfg,
                             textLocStrFmt};

    scopeFc.accept(finder);
    return finder.takeFcDepTypes();
}

} /* namespace src */
} /* namespace ctf */
