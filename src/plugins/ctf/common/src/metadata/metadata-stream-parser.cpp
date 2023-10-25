/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <cstring>

#include "metadata-stream-parser.hpp"
#include "normalize-clk-offset.hpp"

namespace ctf {
namespace src {
namespace {

using namespace bt2c::literals::datalen;

/*
 * Map of variant field class to the index of the currently visited
 * option.
 *
 * This is used to provide a visiting context to an `FcFinder` instance.
 * For example, consider this scope field class:
 *
 * Root: Structure FC                                       [0]
 *   `len`: Fixed-length unsigned integer FC                [1]
 *   `meow`: Dynamic-length array FC                        [2]
 *     Element FC: Structure FC                             [3]
 *       `tag`: Fixed-length signed integer FC              [4]
 *       `val`: Variant FC                                  [5]
 *         `boss`: Null-terminated string FC                [6]
 *         `zoom`: Structure FC                             [7]
 *           `len`: Variable-length unsigned integer FC     [8]
 *           `data`: Dynamic-length BLOB FC                 [9]
 *         `line6`: Structure FC                            [10]
 *           `len`: Fixed-length unsigned integer FC        [11]
 *
 * If we're currently visiting [9] to find its dependencies, then the
 * current dynamic indexes would be:
 *
 *     [5] -> 1     (visiting second option (`zoom`) of `/meow/val`)
 *
 * This means that, if the length field location of [9] is
 * `/meow/val/len`, then we must only consider the `zoom` option, not
 * the `line6` one, even though both contain a member class named `len`.
 */
using VariantOptIndexes = std::unordered_map<const Fc *, std::size_t>;

/*
 * Field class visitor to find field classes from a field location and
 * an instance of `VariantOptIndexes` to indicate the current visiting
 * context of the dependent field class.
 */
class FcFinder final : public FcVisitor
{
public:
    explicit FcFinder(const FieldLoc::Items& path, const VariantOptIndexes& dynIndexes) :
        _mPath {&path}, _mPathIter {path.begin()}, _mVariantOptIndexes {&dynIndexes}
    {
    }

    /*
     * Resulting field class set.
     */
    const FcSet& fcs() const noexcept
    {
        return _mFcs;
    }

    void visit(FixedLenBoolFc& fc) override
    {
        this->_addFc(fc);
    }

    void visit(FixedLenUIntFc& fc) override
    {
        this->_addFc(fc);
    }

    void visit(FixedLenSIntFc& fc) override
    {
        this->_addFc(fc);
    }

    void visit(FixedLenSEnumFc& fc) override
    {
        this->_addFc(fc);
    }

    void visit(FixedLenUEnumFc& fc) override
    {
        this->_addFc(fc);
    }

    void visit(VarLenSIntFc& fc) override
    {
        this->_addFc(fc);
    }

    void visit(VarLenUIntFc& fc) override
    {
        this->_addFc(fc);
    }

    void visit(VarLenSEnumFc& fc) override
    {
        this->_addFc(fc);
    }

    void visit(VarLenUEnumFc& fc) override
    {
        this->_addFc(fc);
    }

    void visit(StaticLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(DynLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(StructFc& structFc) override
    {
        BT_ASSERT(_mPathIter != _mPath->end());

        const auto memberCls = structFc[*_mPathIter];

        BT_ASSERT(memberCls);

        /* Go to next path item */
        ++_mPathIter;
        memberCls->fc().accept(*this);

        /* Restore path item */
        --_mPathIter;
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

private:
    void _addFc(Fc& fc)
    {
        /* Must be a leaf! */
        BT_ASSERT(_mPathIter == _mPath->end());

        /* Insert into resulting field class set */
        _mFcs.insert(&fc);
    }

    void _visit(ArrayFc& arrayFc)
    {
        arrayFc.elemFc().accept(*this);
    }

    void _visit(OptionalFc& optFc)
    {
        optFc.fc().accept(*this);
    }

    template <typename VariantFcT>
    void _visitVariantFc(VariantFcT& variantFc)
    {
        const auto optIndexIt = _mVariantOptIndexes->find(&variantFc);

        if (optIndexIt == _mVariantOptIndexes->end()) {
            /*
             * Dependent field class isn't within `variantFc`: consider
             * all options.
             */
            for (auto& opt : variantFc) {
                opt.fc().accept(*this);
            }
        } else {
            /*
             * Dependent field class is within `variantFc`: follow its
             * specific option.
             */
            variantFc[optIndexIt->second].fc().accept(*this);
        }
    }

    const FieldLoc::Items *_mPath;
    FieldLoc::Items::const_iterator _mPathIter;
    const VariantOptIndexes *_mVariantOptIndexes;
    FcSet _mFcs;
};

/*
 * Returns the field class of the scope `scope` considering the context
 * `traceCls`, `dataStreamCls`, and `eventRecordCls`.
 */
Fc& scopeFc(TraceCls& traceCls, DataStreamCls * const dataStreamCls,
            EventRecordCls * const eventRecordCls, const ir::FieldLocScope scope) noexcept
{
    switch (scope) {
    case ir::FieldLocScope::PKT_HEADER:
        return *traceCls.pktHeaderFc();
    case ir::FieldLocScope::PKT_CTX:
        BT_ASSERT(dataStreamCls);
        BT_ASSERT(dataStreamCls->pktCtxFc());
        return *dataStreamCls->pktCtxFc();
    case ir::FieldLocScope::EVENT_RECORD_HEADER:
        BT_ASSERT(dataStreamCls);
        BT_ASSERT(dataStreamCls->eventRecordHeaderFc());
        return *dataStreamCls->eventRecordHeaderFc();
    case ir::FieldLocScope::EVENT_RECORD_COMMON_CTX:
        BT_ASSERT(dataStreamCls);
        BT_ASSERT(dataStreamCls->eventRecordCommonCtxFc());
        return *dataStreamCls->eventRecordCommonCtxFc();
    case ir::FieldLocScope::EVENT_RECORD_SPEC_CTX:
        BT_ASSERT(eventRecordCls);
        BT_ASSERT(eventRecordCls->specCtxFc());
        return *eventRecordCls->specCtxFc();
    case ir::FieldLocScope::EVENT_RECORD_PAYLOAD:
        BT_ASSERT(eventRecordCls);
        BT_ASSERT(eventRecordCls->payloadFc());
        return *eventRecordCls->payloadFc();
    default:
        bt_common_abort();
    }
}

/*
 * Sets the value saving indexes of dependencies and the saved value
 * index of dependent field classes.
 */
class DependentFcSavedValIndexSetter final : public FcVisitor
{
public:
    explicit DependentFcSavedValIndexSetter(TraceCls& traceCls,
                                            DataStreamCls * const curDataStreamCls,
                                            EventRecordCls * const curEventRecordCls) :
        _mTraceCls {&traceCls},
        _mCurDataStreamCls {curDataStreamCls}, _mCurEventRecordCls {curEventRecordCls}
    {
    }

    void visit(StaticLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(DynLenArrayFc& fc) override
    {
        this->_setSavedValIndex(fc, fc.lenFieldLoc());
        this->_visit(fc);
    }

    void visit(DynLenStrFc& fc) override
    {
        this->_setSavedValIndex(fc, fc.lenFieldLoc());
    }

    void visit(DynLenBlobFc& fc) override
    {
        this->_setSavedValIndex(fc, fc.lenFieldLoc());
    }

    void visit(StructFc& structFc) override
    {
        for (auto& memberCls : structFc) {
            memberCls.fc().accept(*this);
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

private:
    /*
     * Sets the saved value index of the dependent field class `fc`,
     * finding the dependencies with `fieldLoc`.
     */
    template <typename FcT>
    void _setSavedValIndex(FcT& fc, const FieldLoc& fieldLoc)
    {
        /* Find the dependencies */
        FcFinder finder {fieldLoc.items(), _mCurVariantOptIndexes};

        scopeFc(*_mTraceCls, _mCurDataStreamCls, _mCurEventRecordCls, fieldLoc.scope())
            .accept(finder);

        /* Value saving index to use */
        const auto valSavingIndex = _mTraceCls->savedValCount();

        /* Update maximum number of saved values of `*_mTraceCls` */
        _mTraceCls->savedValCount(valSavingIndex + 1);

        /* Add value saving index to all dependencies */
        for (const auto foundFc : finder.fcs()) {
            if (foundFc->isFixedLenBool()) {
                foundFc->asFixedLenBool().addValSavingIndex(valSavingIndex);
            } else if (foundFc->isFixedLenInt()) {
                foundFc->asFixedLenInt().addValSavingIndex(valSavingIndex);
            } else {
                BT_ASSERT(foundFc->isVarLenInt());
                foundFc->asVarLenInt().addValSavingIndex(valSavingIndex);
            }
        }

        /* Set saved value index of dependent field class `fc` */
        fc.savedDepValIndex(valSavingIndex);

        /* Set dependencies of dependent field class `fc` */
        fc.deps(finder.fcs());
    }

    void _visit(ArrayFc& arrayFc)
    {
        arrayFc.elemFc().accept(*this);
    }

    void _visit(OptionalFc& optFc)
    {
        this->_setSavedValIndex(optFc, optFc.selFieldLoc());
        optFc.fc().accept(*this);
    }

    template <typename VariantFcT>
    void _visitVariantFc(VariantFcT& variantFc)
    {
        this->_setSavedValIndex(variantFc, variantFc.selFieldLoc());

        for (std::size_t i = 0; i < variantFc.size(); ++i) {
            /*
             * Mark this option as being visited for this variant field
             * class, then visit the field class of the option, then
             * finally unmark this option.
             */
            _mCurVariantOptIndexes.insert(std::make_pair(&variantFc, i));
            variantFc[i].fc().accept(*this);
            _mCurVariantOptIndexes.erase(&variantFc);
        }
    }

    TraceCls *_mTraceCls;
    DataStreamCls *_mCurDataStreamCls;
    EventRecordCls *_mCurEventRecordCls;
    VariantOptIndexes _mCurVariantOptIndexes;
};

/*
 * Helper containing context to implement setSavedValIndexes().
 */
class SavedValIndexesSetter final
{
public:
    explicit SavedValIndexesSetter(TraceCls& traceCls) : _mTraceCls {&traceCls}
    {
        /* Process whole trace class */
        this->_setSavedValIndexes();
    }

private:
    /*
     * Sets the saved value indexes within the scope field class
     * `structFc`, if it exists.
     */
    void _setSavedValIndexes(StructFc * const structFc)
    {
        if (!structFc) {
            /* Scope doesn't exist */
            return;
        }

        /* Create setter for dependent field classes */
        DependentFcSavedValIndexSetter setter {*_mTraceCls, _mCurDataStreamCls,
                                               _mCurEventRecordCls};

        /*
         * Visit scope field class.
         *
         * During the visit, `setter` calls savedDepValIndex() for each
         * dependent field class as well as TraceCls::savedValCount() to
         * update the total count of saved values.
         */
        structFc->accept(setter);
    }

    /*
     * Sets the saved value indexes within `eventRecordCls`.
     */
    void _setSavedValIndexes(EventRecordCls& eventRecordCls)
    {
        if (eventRecordCls.libCls()) {
            /* Already done */
            return;
        }

        _mCurEventRecordCls = &eventRecordCls;

        /* Process specific context field class */
        this->_setSavedValIndexes(eventRecordCls.specCtxFc());

        /* Process payload field class */
        this->_setSavedValIndexes(eventRecordCls.payloadFc());

        /* Not visiting anymore */
        _mCurEventRecordCls = nullptr;
    }

    /*
     * Sets the saved value indexes within `dataStreamCls`.
     */
    void _setSavedValIndexes(DataStreamCls& dataStreamCls)
    {
        _mCurDataStreamCls = &dataStreamCls;

        if (!dataStreamCls.libCls()) {
            /* Process packet context field class */
            this->_setSavedValIndexes(dataStreamCls.pktCtxFc());

            /* Process event record header field class */
            this->_setSavedValIndexes(dataStreamCls.eventRecordHeaderFc());

            /* Process common event record context field class */
            this->_setSavedValIndexes(dataStreamCls.eventRecordCommonCtxFc());
        }

        /* Process event record classes */
        for (auto& eventRecordCls : dataStreamCls) {
            this->_setSavedValIndexes(*eventRecordCls);
        }

        /* Not visiting anymore */
        _mCurDataStreamCls = nullptr;
    }

    /*
     * Sets the saved value indexes within `*_mTraceCls`.
     */
    void _setSavedValIndexes()
    {
        if (!_mTraceCls->libCls()) {
            /* Process packet header field class */
            this->_setSavedValIndexes(_mTraceCls->pktHeaderFc());
        }

        /* Process data stream classes */
        for (auto& dataStreamCls : *_mTraceCls) {
            this->_setSavedValIndexes(*dataStreamCls);
        }
    }

    /* Trace class on which we're working */
    TraceCls *_mTraceCls;

    /* Current visited data stream class, if any */
    DataStreamCls *_mCurDataStreamCls = nullptr;

    /* Current visited event record class, if any */
    EventRecordCls *_mCurEventRecordCls = nullptr;
};

void setSavedValIndexes(TraceCls& traceCls)
{
    SavedValIndexesSetter {traceCls};
}

/*
 * Visits a field class recursively to check whether or not it contains
 * an unsigned integer field class having a given role.
 */
class FcContainsUIntFcWithRole final : public ConstFcVisitor
{
public:
    explicit FcContainsUIntFcWithRole(const ir::UIntFieldRole role) noexcept : _mRole {role}
    {
    }

    bool result() const noexcept
    {
        return _mHasRole;
    }

    void visit(const FixedLenUIntFc& fc) override
    {
        this->_updateHasRole(fc);
    }

    void visit(const FixedLenUEnumFc& fc) override
    {
        this->_updateHasRole(fc);
    }

    void visit(const VarLenUIntFc& fc) override
    {
        this->_updateHasRole(fc);
    }

    void visit(const VarLenUEnumFc& fc) override
    {
        this->_updateHasRole(fc);
    }

    void visit(const StaticLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const DynLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const StructFc& structFc) override
    {
        for (auto& memberCls : structFc) {
            memberCls.fc().accept(*this);
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

private:
    template <typename FcT>
    void _updateHasRole(const FcT& fc) noexcept
    {
        _mHasRole = _mHasRole || fc.hasRole(_mRole);
    }

    void _visit(const ArrayFc& arrayFc)
    {
        arrayFc.elemFc().accept(*this);
    }

    void _visit(const OptionalFc& optFc)
    {
        optFc.fc().accept(*this);
    }

    template <typename VariantFcT>
    void _visitVariantFc(const VariantFcT& variantFc)
    {
        for (auto& opt : variantFc) {
            opt.fc().accept(*this);
        }
    }

    ir::UIntFieldRole _mRole;
    bool _mHasRole = false;
};

bool fcContainsUIntFcWithRole(const Fc& fc, const ir::UIntFieldRole role) noexcept
{
    FcContainsUIntFcWithRole visitor {role};

    fc.accept(visitor);
    return visitor.result();
}

bool pktCtxFcContainsUIntFcWithRole(const DataStreamCls& dataStreamCls,
                                    const ir::UIntFieldRole role) noexcept
{
    return dataStreamCls.pktCtxFc() && fcContainsUIntFcWithRole(*dataStreamCls.pktCtxFc(), role);
}

/*
 * Sets the user attributes of the equivalent trace IR object of `obj`
 * (`obj.libCls()`) to the user attributes of `obj`.
 */
template <typename ObjT>
void setLibUserAttrs(ObjT& obj) noexcept
{
    if (obj.userAttrs()) {
        BT_ASSERT(obj.libCls());
        obj.libCls()->userAttributes(*obj.userAttrs());
    }
}

/*
 * Translates `ranges` to its libbabeltrace2 equivalent (of type
 * `LibIntRangeSetT`) and returns it.
 */
template <typename LibIntRangeSetT, typename IntRangeSetT>
typename LibIntRangeSetT::Shared libIntRangeSetFromIntRangeSet(const IntRangeSetT& ranges)
{
    auto libRanges = LibIntRangeSetT::create();

    for (auto& range : ranges) {
        libRanges->addRange(range.lower(), range.upper());
    }

    return libRanges;
}

bt2::UnsignedIntegerRangeSet::Shared libIntRangeSetFromIntRangeSet(const UIntRangeSet& ranges)
{
    return libIntRangeSetFromIntRangeSet<bt2::UnsignedIntegerRangeSet>(ranges);
}

bt2::SignedIntegerRangeSet::Shared libIntRangeSetFromIntRangeSet(const SIntRangeSet& ranges)
{
    return libIntRangeSetFromIntRangeSet<bt2::SignedIntegerRangeSet>(ranges);
}

/*
 * Helper containing context to implement libFcFromFc().
 */
class LibFcFromFcTranslator final : public FcVisitor
{
public:
    explicit LibFcFromFcTranslator(TraceCls& traceCls, const unsigned long long mipVersion) :
        _mTraceCls {&traceCls}, _mMipVersion {mipVersion}
    {
        BT_ASSERT(traceCls.libCls());
    }

    bt2::FieldClass::Shared libFc() noexcept
    {
        return _mLastTranslatedLibFc;
    }

    void visit(FixedLenBitArrayFc& fc) override
    {
        this->_setLibFc(fc, _mTraceCls->libCls()->createBitArrayFieldClass(*fc.len()));
    }

    void visit(FixedLenBoolFc& fc) override
    {
        this->_setLibFc(fc, _mTraceCls->libCls()->createBoolFieldClass());
    }

    void visit(FixedLenFloatFc& fc) override
    {
        if (fc.len() == 32_bits) {
            this->_setLibFc(fc, _mTraceCls->libCls()->createSinglePrecisionRealFieldClass());
        } else {
            BT_ASSERT(fc.len() == 64_bits);
            this->_setLibFc(fc, _mTraceCls->libCls()->createDoublePrecisionRealFieldClass());
        }
    }

    void visit(FixedLenSIntFc& fc) override
    {
        this->_setLibIntFc<_CreateLibSIntFcFunc>(fc, fc.len());
    }

    void visit(FixedLenUIntFc& fc) override
    {
        this->_setLibUIntFc<_CreateLibUIntFcFunc>(fc, fc.len());
    }

    void visit(FixedLenUEnumFc& fc) override
    {
        this->_setLibUEnumFc(fc, fc.len());
    }

    void visit(FixedLenSEnumFc& fc) override
    {
        this->_setLibSEnumFc(fc, fc.len());
    }

    void visit(VarLenSIntFc& fc) override
    {
        this->_setLibIntFc<_CreateLibSIntFcFunc>(fc, 64_bits);
    }

    void visit(VarLenUIntFc& fc) override
    {
        this->_setLibUIntFc<_CreateLibUIntFcFunc>(fc, 64_bits);
    }

    void visit(VarLenUEnumFc& fc) override
    {
        this->_setLibUEnumFc(fc, 64_bits);
    }

    void visit(VarLenSEnumFc& fc) override
    {
        this->_setLibSEnumFc(fc, 64_bits);
    }

    void visit(NullTerminatedStrFc& fc) override
    {
        this->_setLibFc(fc, _mTraceCls->libCls()->createStringFieldClass());
    }

    void visit(StaticLenStrFc& fc) override
    {
        this->_setLibFc(fc, _mTraceCls->libCls()->createStringFieldClass());
    }

    void visit(DynLenStrFc& fc) override
    {
        this->_setLibFc(fc, _mTraceCls->libCls()->createStringFieldClass());
    }

    void visit(StaticLenBlobFc& fc) override
    {
        BT_ASSERT(_mMipVersion >= 1);
        this->_setLibBlobFc(fc, _mTraceCls->libCls()->createStaticBlobFieldClass(fc.len()));
    }

    void visit(DynLenBlobFc& fc) override
    {
        BT_ASSERT(_mMipVersion >= 1);

        const auto fieldLoc = this->_libFieldLocFromFieldLoc(fc.lenFieldLoc());

        if (fieldLoc) {
            this->_setLibBlobFc(
                fc, _mTraceCls->libCls()->createDynamicBlobWithLengthFieldLocationFieldClass(
                        *fieldLoc));
        } else {
            this->_setLibBlobFc(
                fc, _mTraceCls->libCls()->createDynamicBlobWithoutLengthFieldLocationFieldClass());
        }
    }

    void visit(StaticLenArrayFc& fc) override
    {
        /* Try to translate element field class */
        this->_visit(fc);

        /*
         * `_mLastTranslatedLibFc` is the element field class.
         *
         * If it's not set, then the element field class itself has no
         * trace IR translation, ergo `fc` has no trace IR translation.
         */
        if (!_mLastTranslatedLibFc) {
            return;
        }

        this->_setLibFc(fc, _mTraceCls->libCls()->createStaticArrayFieldClass(
                                *_mLastTranslatedLibFc, fc.len()));
    }

    void visit(DynLenArrayFc& fc) override
    {
        /* Try to translate element field class */
        this->_visit(fc);

        /*
         * `_mLastTranslatedLibFc` is the element field class.
         *
         * If it's not set, then the element field class itself has no
         * trace IR translation, ergo `fc` has no trace IR translation.
         */
        if (!_mLastTranslatedLibFc) {
            return;
        }

        /* Finish translation */
        this->_finishTranslateDynFc<_CreateLibDynLenArrayFcFuncs>(fc, fc.lenFieldLoc());
    }

    void visit(StructFc& structFc) override
    {
        /* Create empty trace IR structure field class and keep it */
        auto libStructFc = _mTraceCls->libCls()->createStructureFieldClass();

        /* Assign as translation and set user attributes */
        structFc.libCls(*libStructFc);
        setLibUserAttrs(structFc);

        /* Translate member classes */
        for (auto& memberCls : structFc) {
            /* Try to translate field class of member class */
            memberCls.fc().accept(*this);

            /*
             * `_mLastTranslatedLibFc` is the field class of this member
             * class.
             *
             * If it's not set, then the member class itself has no
             * trace IR translation.
             */
            if (!_mLastTranslatedLibFc) {
                continue;
            }

            /* Append new member class */
            libStructFc->appendMember(memberCls.name(), *_mLastTranslatedLibFc);

            /* Set user attributes of member class, if any */
            if (memberCls.userAttrs()) {
                (*libStructFc)[libStructFc->length() - 1].userAttributes(*memberCls.userAttrs());
            }
        }

        /*
         * Set translated structure field class as last translated field
         * class.
         */
        _mLastTranslatedLibFc = std::move(libStructFc);
    }

    void visit(OptionalWithBoolSelFc& fc) override
    {
        /* Try to translate optional field class */
        this->_visit(fc);

        /*
         * `_mLastTranslatedLibFc` is the optional field class.
         *
         * If it's not set, then the optional field class itself has no
         * trace IR translation, ergo `fc` has no trace IR translation.
         */
        if (!_mLastTranslatedLibFc) {
            return;
        }

        /* Finish translation */
        this->_finishTranslateDynFc<_CreateLibOptWithBoolSelFcFuncs>(fc, fc.selFieldLoc());
    }

    void visit(OptionalWithUIntSelFc& fc) override
    {
        /* Try to translate optional field class */
        this->_visit(fc);

        /*
         * `_mLastTranslatedLibFc` is the optional field class.
         *
         * If it's not set, then the optional field class itself has no
         * trace IR translation, ergo `fc` has no trace IR translation.
         */
        if (!_mLastTranslatedLibFc) {
            return;
        }

        /* Finish translation */
        this->_finishTranslateDynFc<_CreateLibOptWithUIntSelFcFuncs>(fc, fc.selFieldLoc());
    }

    void visit(OptionalWithSIntSelFc& fc) override
    {
        /* Try to translate optional field class */
        this->_visit(fc);

        /*
         * `_mLastTranslatedLibFc` is the optional field class.
         *
         * If it's not set, then the optional field class itself has no
         * trace IR translation, ergo `fc` has no trace IR translation.
         */
        if (!_mLastTranslatedLibFc) {
            return;
        }

        /* Finish translation */
        this->_finishTranslateDynFc<_CreateLibOptWithSIntSelFcFuncs>(fc, fc.selFieldLoc());
    }

    void visit(VariantWithUIntSelFc& fc) override
    {
        this->_visitVariantFc<bt2::VariantWithUnsignedIntegerSelectorFieldClass,
                              _CreateLibVariantWithUIntSelFcFuncs>(fc);
    }

    void visit(VariantWithSIntSelFc& fc) override
    {
        this->_visitVariantFc<bt2::VariantWithSignedIntegerSelectorFieldClass,
                              _CreateLibVariantWithSIntSelFcFuncs>(fc);
    }

private:
    /*
     * If the scope of `fieldLoc` is the packet header, the packet
     * context, or the event record header: returns an empty `Shared`.
     *
     * Otherwise, translates `fieldLoc` to its trace IR equivalent and
     * returns it.
     */
    bt2::ConstFieldLocation::Shared _libFieldLocFromFieldLoc(const FieldLoc& fieldLoc) const
    {
        BT_ASSERT(_mMipVersion >= 1);

        if (fieldLoc.scope() == ir::FieldLocScope::PKT_HEADER ||
            fieldLoc.scope() == ir::FieldLocScope::PKT_CTX ||
            fieldLoc.scope() == ir::FieldLocScope::EVENT_RECORD_HEADER) {
            /*
             * We could support referring to a packet context field, but
             * because such a field could have a role and therefore not
             * have a trace IR translation, we don't take a chance.
             */
            return bt2::ConstFieldLocation::Shared {};
        }

        const auto scope = [&fieldLoc] {
            switch (fieldLoc.scope()) {
            case ir::FieldLocScope::EVENT_RECORD_COMMON_CTX:
                return bt2::ConstFieldLocation::Scope::EVENT_COMMON_CONTEXT;
            case ir::FieldLocScope::EVENT_RECORD_SPEC_CTX:
                return bt2::ConstFieldLocation::Scope::EVENT_SPECIFIC_CONTEXT;
            case ir::FieldLocScope::EVENT_RECORD_PAYLOAD:
                return bt2::ConstFieldLocation::Scope::EVENT_PAYLOAD;
            default:
                bt_common_abort();
            }
        }();

        return _mTraceCls->libCls()->createFieldLocation(scope, fieldLoc.items());
    }

    /*
     * Sets the trace IR translation of `fc` to `libFc`, sets the user
     * attributes of `libFc` from `fc`, and then moves `libFc` as the
     * last translated trace IR field class.
     */
    template <typename FcT>
    void _setLibFc(FcT& fc, bt2::FieldClass::Shared libFc) noexcept
    {
        fc.libCls(*libFc);
        setLibUserAttrs(fc);
        _mLastTranslatedLibFc = std::move(libFc);
    }

    struct _CreateLibUIntFcFunc final
    {
        static bt2::IntegerFieldClass::Shared create(bt2::TraceClass traceCls)
        {
            return traceCls.createUnsignedIntegerFieldClass();
        }
    };

    struct _CreateLibSIntFcFunc final
    {
        static bt2::IntegerFieldClass::Shared create(bt2::TraceClass traceCls)
        {
            return traceCls.createSignedIntegerFieldClass();
        }
    };

    struct _CreateLibUEnumFcFunc final
    {
        static bt2::UnsignedEnumerationFieldClass::Shared create(bt2::TraceClass traceCls)
        {
            return traceCls.createUnsignedEnumerationFieldClass();
        }
    };

    struct _CreateLibSEnumFcFunc final
    {
        static bt2::SignedEnumerationFieldClass::Shared create(bt2::TraceClass traceCls)
        {
            return traceCls.createSignedEnumerationFieldClass();
        }
    };

    /*
     * Translates `fc`, an integer field class of which the instances
     * have a maximum length of `len`, to its trace IR equivalent, and
     * then moves it as the last translated trace IR field class.
     *
     * Uses `CreateLibFcFuncT::create()` to create a trace IR integer
     * field class.
     */
    template <typename CreateLibFcFuncT, typename FcT>
    void _setLibIntFc(FcT& fc, const bt2c::DataLen len)
    {
        /* Create trace IR field class */
        auto libFc = CreateLibFcFuncT::create(*_mTraceCls->libCls());

        /* Set field value range (bits) */
        libFc->fieldValueRange(*len);

        /* Set preferred display base */
        libFc->preferredDisplayBase([&fc] {
            switch (fc.prefDispBase()) {
            case ir::DispBase::BIN:
                return bt2::DisplayBase::Binary;
            case ir::DispBase::OCT:
                return bt2::DisplayBase::Octal;
            case ir::DispBase::DEC:
                return bt2::DisplayBase::Decimal;
            case ir::DispBase::HEX:
                return bt2::DisplayBase::Hexadecimal;
            default:
                bt_common_abort();
            }
        }());

        /* Assign as translation */
        this->_setLibFc(fc, std::move(libFc));
    }

    /*
     * If `fc`, an unsigned integer field class, has at least one
     * role: returns immediately.
     *
     * Otherwise, translates `fc`, of which the instances have a maximum
     * length of `len`, to its trace IR equivalent, and then moves it as
     * the last translated trace IR field class.
     *
     * Uses `CreateLibFcFuncT::create()` to create a trace IR unsigned
     * integer field class.
     */
    template <typename CreateLibFcFuncT, typename FcT>
    void _setLibUIntFc(FcT& fc, const bt2c::DataLen len)
    {
        if (!fc.roles().empty()) {
            /* Field class has a role: don't translate it to trace IR */
            _mLastTranslatedLibFc = bt2::FieldClass::Shared {};
            return;
        }

        this->_setLibIntFc<CreateLibFcFuncT>(fc, len);
    }

    /*
     * Sets the mappings of `libFc`, a trace IR enumeration field class,
     * to the mappings of `fc`, a CTF IR enumeration field class.
     */
    template <typename FcT, typename LibFcT>
    void _setLibEnumFcMappings(const FcT& fc, LibFcT libFc)
    {
        for (auto& mapping : fc.mappings()) {
            const auto libRanges = libIntRangeSetFromIntRangeSet(mapping.second);

            libFc.addMapping(mapping.first, *libRanges);
        }
    }

    /*
     * If `fc`, an unsigned enumeration field class, has at least one
     * role: returns immediately.
     *
     * Otherwise, translates `fc`, of which the instances have a maximum
     * length of `len`, to its trace IR equivalent, and then moves it as
     * the last translated trace IR field class.
     */
    template <typename FcT>
    void _setLibUEnumFc(FcT& fc, const bt2c::DataLen len)
    {
        this->_setLibUIntFc<_CreateLibUEnumFcFunc>(fc, len);

        if (!_mLastTranslatedLibFc) {
            /* Not translated */
            return;
        }

        this->_setLibEnumFcMappings(fc, _mLastTranslatedLibFc->asUnsignedEnumeration());
    }

    /*
     * Translates `fc`, a signed enumeration field class of which the
     * instances have a maximum length of `len`, to its trace IR
     * equivalent, and then moves it as the last translated trace IR
     * field class.
     */
    template <typename FcT>
    void _setLibSEnumFc(FcT& fc, const bt2c::DataLen len)
    {
        this->_setLibIntFc<_CreateLibSEnumFcFunc>(fc, len);
        BT_ASSERT(_mLastTranslatedLibFc);
        this->_setLibEnumFcMappings(fc, _mLastTranslatedLibFc->asSignedEnumeration());
    }

    /*
     * Sets the trace IR translation of `fc` to `libFc`, a trace IR BLOB
     * field class, also setting the media type of `libFc` from `fc`,
     * and then moves `libFc` as the last translated trace IR field
     * class.
     */
    template <typename FcT, typename SharedLibFcT>
    void _setLibBlobFc(FcT& fc, SharedLibFcT libFc)
    {
        /* Set media type */
        libFc->mediaType(fc.mediaType());

        /* Assign as translation */
        this->_setLibFc(fc, std::move(libFc));
    }

    struct _CreateLibDynLenArrayFcFuncs final
    {
        using RetWithout = bt2::ArrayFieldClass::Shared;
        using RetWith = bt2::DynamicArrayWithLengthFieldClass::Shared;

        static RetWithout mip0Without(TraceCls& traceCls, DynLenArrayFc&,
                                      const bt2::FieldClass::Shared& lastTranslatedLibFc)
        {
            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createDynamicArrayFieldClass(*lastTranslatedLibFc);
        }

        static RetWith mip0With(TraceCls& traceCls, DynLenArrayFc&,
                                const bt2::FieldClass::Shared& lastTranslatedLibFc,
                                const bt2::FieldClass libDepFc)
        {
            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createDynamicArrayFieldClass(*lastTranslatedLibFc,
                                                                   libDepFc.asInteger());
        }

        static RetWithout mip1Without(TraceCls& traceCls, DynLenArrayFc&,
                                      const bt2::FieldClass::Shared& lastTranslatedLibFc)
        {
            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createDynamicArrayWithoutLengthFieldLocationFieldClass(
                *lastTranslatedLibFc);
        }

        static RetWith mip1With(TraceCls& traceCls, DynLenArrayFc&,
                                const bt2::FieldClass::Shared& lastTranslatedLibFc,
                                const bt2::ConstFieldLocation libFieldLoc)
        {
            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createDynamicArrayWithLengthFieldLocationFieldClass(
                *lastTranslatedLibFc, libFieldLoc);
        }
    };

    struct _CreateLibOptWithBoolSelFcFuncs final
    {
        using RetWithout = bt2::OptionFieldClass::Shared;
        using RetWith = bt2::OptionWithBoolSelectorFieldClass::Shared;

        static RetWithout mip0Without(TraceCls& traceCls, OptionalFc&,
                                      const bt2::FieldClass::Shared& lastTranslatedLibFc)
        {
            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createOptionFieldClass(*lastTranslatedLibFc);
        }

        static RetWith mip0With(TraceCls& traceCls, OptionalFc&,
                                const bt2::FieldClass::Shared& lastTranslatedLibFc,
                                const bt2::FieldClass libDepFc)
        {
            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createOptionWithBoolSelectorFieldClass(*lastTranslatedLibFc,
                                                                             libDepFc);
        }

        static RetWithout mip1Without(TraceCls& traceCls, OptionalFc&,
                                      const bt2::FieldClass::Shared& lastTranslatedLibFc)
        {
            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createOptionWithoutSelectorFieldLocationFieldClass(
                *lastTranslatedLibFc);
        }

        static RetWith mip1With(TraceCls& traceCls, OptionalFc&,
                                const bt2::FieldClass::Shared& lastTranslatedLibFc,
                                const bt2::ConstFieldLocation libFieldLoc)
        {
            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createOptionWithBoolSelectorFieldLocationFieldClass(
                *lastTranslatedLibFc, libFieldLoc);
        }
    };

    struct _CreateLibOptWithUIntSelFcFuncs final
    {
        using RetWithout = bt2::OptionFieldClass::Shared;
        using RetWith = bt2::OptionWithUnsignedIntegerSelectorFieldClass::Shared;

        static RetWithout mip0Without(TraceCls& traceCls, OptionalFc&,
                                      const bt2::FieldClass::Shared& lastTranslatedLibFc)
        {
            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createOptionFieldClass(*lastTranslatedLibFc);
        }

        static RetWith mip0With(TraceCls& traceCls, OptionalWithUIntSelFc& fc,
                                const bt2::FieldClass::Shared& lastTranslatedLibFc,
                                const bt2::FieldClass libDepFc)
        {
            const auto libRangeSet = libIntRangeSetFromIntRangeSet(fc.selFieldRanges());

            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createOptionWithUnsignedIntegerSelectorFieldClass(
                *lastTranslatedLibFc, libDepFc.asInteger(), *libRangeSet);
        }

        static RetWithout mip1Without(TraceCls& traceCls, OptionalFc&,
                                      const bt2::FieldClass::Shared& lastTranslatedLibFc)
        {
            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createOptionWithoutSelectorFieldLocationFieldClass(
                *lastTranslatedLibFc);
        }

        static RetWith mip1With(TraceCls& traceCls, OptionalWithUIntSelFc& fc,
                                const bt2::FieldClass::Shared& lastTranslatedLibFc,
                                const bt2::ConstFieldLocation libFieldLoc)
        {
            const auto libRangeSet = libIntRangeSetFromIntRangeSet(fc.selFieldRanges());

            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()
                ->createOptionWithUnsignedIntegerSelectorFieldLocationFieldClass(
                    *lastTranslatedLibFc, libFieldLoc, *libRangeSet);
        }
    };

    struct _CreateLibOptWithSIntSelFcFuncs final
    {
        using RetWithout = bt2::OptionFieldClass::Shared;
        using RetWith = bt2::OptionWithSignedIntegerSelectorFieldClass::Shared;

        static RetWithout mip0Without(TraceCls& traceCls, OptionalFc&,
                                      const bt2::FieldClass::Shared& lastTranslatedLibFc)
        {
            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createOptionFieldClass(*lastTranslatedLibFc);
        }

        static RetWith mip0With(TraceCls& traceCls, OptionalWithSIntSelFc& fc,
                                const bt2::FieldClass::Shared& lastTranslatedLibFc,
                                const bt2::FieldClass libDepFc)
        {
            const auto libRangeSet = libIntRangeSetFromIntRangeSet(fc.selFieldRanges());

            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createOptionWithSignedIntegerSelectorFieldClass(
                *lastTranslatedLibFc, libDepFc.asInteger(), *libRangeSet);
        }

        static RetWithout mip1Without(TraceCls& traceCls, OptionalFc&,
                                      const bt2::FieldClass::Shared& lastTranslatedLibFc)
        {
            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createOptionWithoutSelectorFieldLocationFieldClass(
                *lastTranslatedLibFc);
        }

        static RetWith mip1With(TraceCls& traceCls, OptionalWithSIntSelFc& fc,
                                const bt2::FieldClass::Shared& lastTranslatedLibFc,
                                const bt2::ConstFieldLocation libFieldLoc)
        {
            const auto libRangeSet = libIntRangeSetFromIntRangeSet(fc.selFieldRanges());

            BT_ASSERT(lastTranslatedLibFc);
            return traceCls.libCls()->createOptionWithSignedIntegerSelectorFieldLocationFieldClass(
                *lastTranslatedLibFc, libFieldLoc, *libRangeSet);
        }
    };

    struct _CreateLibVariantWithUIntSelFcFuncs final
    {
        using FcParam = VariantWithUIntSelFc;
        using RetWithout = bt2::VariantFieldClass::Shared;
        using RetWith = bt2::VariantWithUnsignedIntegerSelectorFieldClass::Shared;

        static RetWithout mip0Without(TraceCls& traceCls, FcParam&, const bt2::FieldClass::Shared&)
        {
            return traceCls.libCls()->createVariantFieldClass();
        }

        static RetWith mip0With(TraceCls& traceCls, FcParam&, const bt2::FieldClass::Shared&,
                                const bt2::FieldClass libDepFc)
        {
            return traceCls.libCls()->createVariantWithUnsignedIntegerSelectorFieldClass(
                libDepFc.asInteger());
        }

        static RetWithout mip1Without(TraceCls& traceCls, FcParam&, const bt2::FieldClass::Shared&)
        {
            return traceCls.libCls()->createVariantWithoutSelectorFieldLocationFieldClass();
        }

        static RetWith mip1With(TraceCls& traceCls, FcParam&, const bt2::FieldClass::Shared&,
                                const bt2::ConstFieldLocation libFieldLoc)
        {
            return traceCls.libCls()
                ->createVariantWithUnsignedIntegerSelectorFieldLocationFieldClass(libFieldLoc);
        }
    };

    struct _CreateLibVariantWithSIntSelFcFuncs final
    {
        using FcParam = VariantWithSIntSelFc;
        using RetWithout = bt2::VariantFieldClass::Shared;
        using RetWith = bt2::VariantWithSignedIntegerSelectorFieldClass::Shared;

        static RetWithout mip0Without(TraceCls& traceCls, FcParam&, const bt2::FieldClass::Shared&)
        {
            return traceCls.libCls()->createVariantFieldClass();
        }

        static RetWith mip0With(TraceCls& traceCls, FcParam&, const bt2::FieldClass::Shared&,
                                const bt2::FieldClass libDepFc)
        {
            return traceCls.libCls()->createVariantWithSignedIntegerSelectorFieldClass(
                libDepFc.asInteger());
        }

        static RetWithout mip1Without(TraceCls& traceCls, FcParam&, const bt2::FieldClass::Shared&)
        {
            return traceCls.libCls()->createVariantWithoutSelectorFieldLocationFieldClass();
        }

        static RetWith mip1With(TraceCls& traceCls, FcParam&, const bt2::FieldClass::Shared&,
                                const bt2::ConstFieldLocation libFieldLoc)
        {
            return traceCls.libCls()->createVariantWithSignedIntegerSelectorFieldLocationFieldClass(
                libFieldLoc);
        }
    };

    /*
     * Finishes translating a dynamic field class `fc` to its trace IR
     * equivalent using, depending on the effective MIP version and on
     * the dependencies, one of the following static methods of
     * `CreateLibFcFuncsT`:
     *
     * mip0Without():
     *    Creates and returns a shared dynamic field class for MIP 0
     *    without a length/selector.
     *
     * mip0With():
     *    Creates and returns a shared dynamic field class for MIP 0
     *    with a length/selector (libbabeltrace2 uses a single field
     *    class to deduce the field path).
     *
     * mip1Without():
     *    Creates and returns a shared dynamic field class for MIP 1
     *    without a length/selector.
     *
     * mip1With():
     *    Creates and returns a shared dynamic field class for MIP 1
     *    without a length/selector (libbabeltrace2 uses a field
     *    location).
     *
     * This method template always calls _setLibFc(). Therefore, after
     * calling this method template, you may modify the created trace IR
     * dynamic field class through `_mLastTranslatedLibFc`.
     */
    template <typename CreateLibFcFuncsT, typename FcT>
    void _finishTranslateDynFc(FcT& fc, const FieldLoc& fieldLoc)
    {
        if (_mMipVersion == 0) {
            /* MIP 0 only knows field paths */
            BT_ASSERT(fc.deps().size() == 1);

            const auto depFc = *fc.deps().begin();

            if (depFc->libCls()) {
                this->_setLibFc(fc, CreateLibFcFuncsT::mip0With(
                                        *_mTraceCls, fc, _mLastTranslatedLibFc, *depFc->libCls()));
            } else {
                /*
                 * Length/selector field class has no trace IR
                 * translation: translate to a field class without a
                 * length/selector field.
                 */
                this->_setLibFc(
                    fc, CreateLibFcFuncsT::mip0Without(*_mTraceCls, fc, _mLastTranslatedLibFc));
            }
        } else {
            /* MIP 1 knows field locations */
            const auto libFieldLoc = this->_libFieldLocFromFieldLoc(fieldLoc);

            if (libFieldLoc) {
                this->_setLibFc(fc, CreateLibFcFuncsT::mip1With(
                                        *_mTraceCls, fc, _mLastTranslatedLibFc, *libFieldLoc));
            } else {
                this->_setLibFc(
                    fc, CreateLibFcFuncsT::mip1Without(*_mTraceCls, fc, _mLastTranslatedLibFc));
            }
        }
    }

    void _visit(ArrayFc& arrayFc)
    {
        arrayFc.elemFc().accept(*this);
    }

    void _visit(OptionalFc& optFc)
    {
        optFc.fc().accept(*this);
    }

    template <typename LibVariantWithSelectorFcT, typename VariantFc>
    void _appendLibVariantFcOpts(VariantFc& fc)
    {
        auto libVariantFc = _mLastTranslatedLibFc->asVariant();

        for (auto& opt : fc.opts()) {
            if (opt.fc().libCls()) {
                /* Translated to trace IR */
                if (libVariantFc.isVariantWithoutSelector()) {
                    auto specLibVariantFc = libVariantFc.asVariantWithoutSelector();

                    specLibVariantFc.appendOption(opt.name(), *opt.fc().libCls());
                } else {
                    auto specLibVariantFc = libVariantFc.as<LibVariantWithSelectorFcT>();
                    const auto libRanges = libIntRangeSetFromIntRangeSet(opt.selFieldRanges());

                    specLibVariantFc.appendOption(opt.name(), *opt.fc().libCls(), *libRanges);
                }

                /* Set user attributes of option, if any */
                if (opt.userAttrs()) {
                    libVariantFc[libVariantFc.length() - 1].userAttributes(*opt.userAttrs());
                }
            }
        }
    }

    template <typename LibVariantWithSelectorFcT, typename CreateLibFcFuncsT, typename VariantFcT>
    void _visitVariantFc(VariantFcT& fc)
    {
        /*
         * Translate options first.
         *
         * If all options have no translation, then `fc` has no
         * translation.
         *
         * The only purpose of `libOpts` is to keep the translated field
         * classes alive until we append the options to the translated
         * variant field class (when calling _appendLibVariantFcOpts()
         * at the end of this method).
         */
        std::vector<bt2::FieldClass::Shared> libOpts;

        for (auto& opt : fc.opts()) {
            /* Try to translate field class of option */
            opt.fc().accept(*this);

            /*
             * `_mLastTranslatedLibFc` is the field class of this
             * option.
             *
             * If it's not set, then the option itself has no trace IR
             * translation.
             */
            if (!_mLastTranslatedLibFc) {
                continue;
            }

            /* Keep this option */
            libOpts.emplace_back(std::move(_mLastTranslatedLibFc));
            _mLastTranslatedLibFc.reset();
        }

        if (libOpts.empty()) {
            /* No options mean no trace IR translation */
            return;
        }

        /* Finish translation */
        this->_finishTranslateDynFc<CreateLibFcFuncsT>(fc, fc.selFieldLoc());

        /* Finally, append options */
        this->_appendLibVariantFcOpts<LibVariantWithSelectorFcT>(fc);
    }

    TraceCls *_mTraceCls;
    unsigned long long _mMipVersion;
    bt2::FieldClass::Shared _mLastTranslatedLibFc;
};

/*
 * Returns the equivalent trace IR field class of `fc` within
 * `traceCls` and considering the effective MIP version `mipVersion`.
 *
 * If the return value of this function is set, then for all the field
 * classes recursively contained in `fc` which have an equivalent trace
 * IR field class, Fc::libCls() returns it.
 */
bt2::FieldClass::Shared libFcFromFc(TraceCls& traceCls, const unsigned long long mipVersion, Fc& fc)
{
    LibFcFromFcTranslator translator {traceCls, mipVersion};

    fc.accept(translator);
    return translator.libFc();
}

/*
 * Helper containing context to implement libTraceClsFromTraceCls().
 */
class LibTraceClsFromTraceClsTranslator final
{
public:
    explicit LibTraceClsFromTraceClsTranslator(TraceCls& traceCls,
                                               const bt2::SelfComponent selfComp) :
        _mTraceCls {&traceCls},
        _mSelfComp {selfComp}, _mMipVersion {selfComp.graphMipVersion()}
    {
        /* Translate whole trace class */
        this->_translate();
    }

private:
    /*
     * Translates the scope field class `structFc` and returns the
     * corresponding trace IR structure field class.
     */
    bt2::StructureFieldClass::Shared _translate(StructFc& structFc)
    {
        /* Translate */
        auto libFc = libFcFromFc(*_mTraceCls, _mMipVersion, structFc);

        /* libFcFromFc() always translates a structure field class */
        BT_ASSERT(libFc);
        return libFc->asStructure().shared();
    }

    static constexpr const char *_btUserAttrsNs = "babeltrace.org,2020";
    static constexpr const char *_lttngUserAttrsNs = "lttng.org,2009";

    static bt2::OptionalBorrowedObject<bt2::ConstValue>
    _userAttr(const bt2::ConstMapValue userAttrs, const char * const ns,
              const char * const name) noexcept
    {
        const auto nsMapVal = userAttrs[ns];

        if (!nsMapVal || !nsMapVal->isMap()) {
            return {};
        }

        return nsMapVal->asMap()[name];
    }

    static bt2::OptionalBorrowedObject<bt2::ConstStringValue>
    _strUserAttr(const bt2::ConstMapValue userAttrs, const char * const ns,
                 const char * const name) noexcept
    {
        const auto val = LibTraceClsFromTraceClsTranslator::_userAttr(userAttrs, ns, name);

        if (!val || !val->isString()) {
            return {};
        }

        return val->asString();
    }

    static bt2::OptionalBorrowedObject<bt2::ConstStringValue>
    _strUserAttr(const bt2::ConstMapValue userAttrs, const char * const name) noexcept
    {
        const auto val = LibTraceClsFromTraceClsTranslator::_strUserAttr(
            userAttrs, LibTraceClsFromTraceClsTranslator::_btUserAttrsNs, name);

        if (val) {
            return val;
        }

        return LibTraceClsFromTraceClsTranslator::_strUserAttr(
            userAttrs, LibTraceClsFromTraceClsTranslator::_lttngUserAttrsNs, name);
    }

    /*
     * Translates `eventRecordCls`, adding it to the current data stream
     * class if missing.
     */
    void _translate(EventRecordCls& eventRecordCls, DataStreamCls& dataStreamCls)
    {
        if (eventRecordCls.libCls()) {
            /* Already done */
            return;
        }

        /* Create the trace IR event record class */
        auto libEventRecordCls = dataStreamCls.libCls()->createEventClass(eventRecordCls.id());

        eventRecordCls.libCls(*libEventRecordCls);

        /* Set namespace */
        if (_mMipVersion >= 1 && eventRecordCls.ns()) {
            libEventRecordCls->nameSpace(*eventRecordCls.ns());
        }

        /* Set name */
        if (eventRecordCls.name()) {
            libEventRecordCls->name(*eventRecordCls.name());
        }

        /* Set log level and EMF URI */
        if (eventRecordCls.userAttrs()) {
            /* Set log level */
            {
                const auto userAttr = this->_strUserAttr(*eventRecordCls.userAttrs(), "log-level");

                if (userAttr) {
                    bt2s::optional<bt2::EventClassLogLevel> logLevel;

                    if (std::strcmp(userAttr->value(), "emergency") == 0) {
                        logLevel = bt2::EventClassLogLevel::Emergency;
                    } else if (std::strcmp(userAttr->value(), "alert") == 0) {
                        logLevel = bt2::EventClassLogLevel::Alert;
                    } else if (std::strcmp(userAttr->value(), "critical") == 0) {
                        logLevel = bt2::EventClassLogLevel::Critical;
                    } else if (std::strcmp(userAttr->value(), "error") == 0) {
                        logLevel = bt2::EventClassLogLevel::Error;
                    } else if (std::strcmp(userAttr->value(), "warning") == 0) {
                        logLevel = bt2::EventClassLogLevel::Warning;
                    } else if (std::strcmp(userAttr->value(), "notice") == 0) {
                        logLevel = bt2::EventClassLogLevel::Notice;
                    } else if (std::strcmp(userAttr->value(), "info") == 0) {
                        logLevel = bt2::EventClassLogLevel::Info;
                    } else if (std::strcmp(userAttr->value(), "debug:system") == 0) {
                        logLevel = bt2::EventClassLogLevel::DebugSystem;
                    } else if (std::strcmp(userAttr->value(), "debug:program") == 0) {
                        logLevel = bt2::EventClassLogLevel::DebugProgram;
                    } else if (std::strcmp(userAttr->value(), "debug:process") == 0) {
                        logLevel = bt2::EventClassLogLevel::DebugProcess;
                    } else if (std::strcmp(userAttr->value(), "debug:module") == 0) {
                        logLevel = bt2::EventClassLogLevel::DebugModule;
                    } else if (std::strcmp(userAttr->value(), "debug:unit") == 0) {
                        logLevel = bt2::EventClassLogLevel::DebugUnit;
                    } else if (std::strcmp(userAttr->value(), "debug:function") == 0) {
                        logLevel = bt2::EventClassLogLevel::DebugFunction;
                    } else if (std::strcmp(userAttr->value(), "debug:line") == 0) {
                        logLevel = bt2::EventClassLogLevel::DebugLine;
                    } else if (std::strcmp(userAttr->value(), "debug") == 0) {
                        logLevel = bt2::EventClassLogLevel::Debug;
                    }

                    if (logLevel) {
                        libEventRecordCls->logLevel(*logLevel);
                    }
                }
            }

            /* Set EMF URI */
            {
                const auto userAttr = this->_strUserAttr(*eventRecordCls.userAttrs(), "emf-uri");

                if (userAttr) {
                    libEventRecordCls->emfUri(userAttr->value().data());
                }
            }
        }

        /* Set user attributes */
        setLibUserAttrs(eventRecordCls);

        /* Translate specific context field class, if any */
        if (eventRecordCls.specCtxFc()) {
            libEventRecordCls->specificContextFieldClass(
                *this->_translate(*eventRecordCls.specCtxFc()));
        }

        /* Translate payload field class, if any */
        if (eventRecordCls.payloadFc()) {
            libEventRecordCls->payloadFieldClass(*this->_translate(*eventRecordCls.payloadFc()));
        }
    }

    /*
     * Translates `clkCls` if not already done.
     */
    void _translate(ClkCls& clkCls)
    {
        if (clkCls.libCls()) {
            /* Already done */
            return;
        }

        /* Create trace IR clock class */
        clkCls.sharedLibCls(_mSelfComp.createClockClass());

        /* Set frequency */
        clkCls.libCls()->frequency(clkCls.freq());

        /* Set offset from origin */
        clkCls.libCls()->offsetFromOrigin(
            bt2::ClockOffset {clkCls.offset().seconds(), clkCls.offset().cycles()});

        /* Set precision */
        clkCls.libCls()->precision(clkCls.precision());

        /* Set origin is Unix epoch flag */
        clkCls.libCls()->originIsUnixEpoch(clkCls.originIsUnixEpoch());

        /* Set name */
        clkCls.libCls()->name(clkCls.name());

        /* Set description */
        if (clkCls.descr()) {
            clkCls.libCls()->description(*clkCls.descr());
        }

        /* Set UUID */
        if (clkCls.uuid()) {
            clkCls.libCls()->uuid(*clkCls.uuid());
        }

        /* Set user attributes */
        setLibUserAttrs(clkCls);
    }

    /*
     * Translates `dataStreamCls`, adding it to `_mTraceCls->libCls()`
     * if missing.
     *
     * Also tries to translate all the contained event record classes.
     */
    void _translate(DataStreamCls& dataStreamCls)
    {
        if (!dataStreamCls.libCls()) {
            /* Create the trace IR data stream class */
            auto libDataStreamCls = _mTraceCls->libCls()->createStreamClass(dataStreamCls.id());

            dataStreamCls.libCls(*libDataStreamCls);

            /* Set namespace */
            if (_mMipVersion >= 1 && dataStreamCls.ns()) {
                libDataStreamCls->nameSpace(*dataStreamCls.ns());
            }

            /* Set name */
            if (dataStreamCls.name()) {
                libDataStreamCls->name(*dataStreamCls.name());
            }

            /* Set default clock class, making sure it's translated */
            if (dataStreamCls.defClkCls()) {
                this->_translate(*dataStreamCls.defClkCls());
                libDataStreamCls->defaultClockClass(*dataStreamCls.defClkCls()->libCls());
            }

            /* We're working with our own event record class IDs */
            libDataStreamCls->assignsAutomaticEventClassId(false);

            /* We're working with our own data stream IDs */
            libDataStreamCls->assignsAutomaticStreamId(false);

            /* We always support packets */
            libDataStreamCls->supportsPackets(
                true, pktCtxFcContainsUIntFcWithRole(dataStreamCls, ir::UIntFieldRole::DEF_CLK_TS),
                pktCtxFcContainsUIntFcWithRole(dataStreamCls,
                                               ir::UIntFieldRole::PKT_END_DEF_CLK_TS));

            if (pktCtxFcContainsUIntFcWithRole(dataStreamCls,
                                               ir::UIntFieldRole::DISC_EVENT_RECORD_COUNTER_SNAP)) {
                /* Set that there's discarded event record support */
                libDataStreamCls->supportsDiscardedEvents(true, dataStreamCls.defClkCls());
            }

            if (pktCtxFcContainsUIntFcWithRole(dataStreamCls, ir::UIntFieldRole::PKT_SEQ_NUM)) {
                /* Set that there's discarded packet support */
                libDataStreamCls->supportsDiscardedPackets(true, dataStreamCls.defClkCls());
            }

            /* Set user attributes */
            setLibUserAttrs(dataStreamCls);

            /* Translate packet context field class, if any */
            if (dataStreamCls.pktCtxFc()) {
                const auto fc = this->_translate(*dataStreamCls.pktCtxFc());

                if (fc->length() > 0) {
                    libDataStreamCls->packetContextFieldClass(*fc);
                }
            }

            /* Translate common event record context field class, if any */
            if (dataStreamCls.eventRecordCommonCtxFc()) {
                libDataStreamCls->eventCommonContextFieldClass(
                    *this->_translate(*dataStreamCls.eventRecordCommonCtxFc()));
            }
        }

        /* Translate event record classes */
        for (auto& eventRecordCls : dataStreamCls) {
            this->_translate(*eventRecordCls, dataStreamCls);
        }
    }

    /*
     * Translate `*_mTraceCls`, setting `_mTraceCls->libCls()` if
     * missing.
     *
     * Also tries to translate all the contained data stream classes.
     */
    void _translate()
    {
        if (!_mTraceCls->libCls()) {
            /* Create trace IR trace class */
            _mTraceCls->sharedLibCls(_mSelfComp.createTraceClass());

            /* We're working with our own data stream class IDs */
            _mTraceCls->libCls()->assignsAutomaticStreamClassId(false);

            /* Set user attributes */
            setLibUserAttrs(*_mTraceCls);
        }

        /* Translate data stream classes */
        for (auto& dataStreamCls : *_mTraceCls) {
            this->_translate(*dataStreamCls);
        }
    }

    /* Trace class on which we're working */
    TraceCls *_mTraceCls;

    /* Our source component */
    bt2::SelfComponent _mSelfComp;

    /* Effective MIP version */
    unsigned long long _mMipVersion;
};

/*
 * Returns the number clock cycles which correspond to `ns` ns
 * considering the frequency `freq` Hz.
 */
unsigned long long cyclesFromNs(const unsigned long long freq, const unsigned long long ns)
{
    return (freq == 1000000000ULL) ?
               ns :
               static_cast<unsigned long long>(
                   (static_cast<double>(ns) * static_cast<double>(freq)) / 1e9);
}

/*
 * Normalizes the offset of `clkCls` so that the cycle part is less than
 * the frequency of `clkCls`.
 */
void normalizeClkClsOffset(ClkCls& clkCls) noexcept
{
    const auto offsetParts =
        normalizeClkOffset(clkCls.offset().seconds(), clkCls.offset().cycles(), clkCls.freq());

    clkCls.offset(ir::ClkOffset {offsetParts.first, offsetParts.second});
}

} /* namespace */

MetadataStreamParser::MetadataStreamParser(
    const ClkClsCfg& clkClsCfg,
    const bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp) noexcept :
    _mClkClsCfg(clkClsCfg),
    _mSelfComp {selfComp}
{
}

void MetadataStreamParser::parseSection(const bt2s::span<const std::uint8_t> buffer)
{
    this->_parseSection(buffer);
    this->_finalizeTraceCls();
}

void MetadataStreamParser::_adjustClkClsOffset(ClkCls& clkCls) noexcept
{
    auto offsetSeconds = static_cast<long long>(_mClkClsCfg.offsetSec);
    auto offsetNs = static_cast<long long>(_mClkClsCfg.offsetNanoSec);

    if (offsetSeconds == 0 && offsetNs == 0) {
        return;
    }

    /* Transfer nanoseconds to seconds as much as possible */
    static constexpr auto nsPerSecond = 1000000000LL;

    if (offsetNs < 0) {
        const auto absNs = -offsetNs;
        const auto absExtraSeconds = absNs / nsPerSecond + 1;
        const auto extraSeconds = -absExtraSeconds;

        offsetNs -= extraSeconds * nsPerSecond;
        BT_ASSERT(offsetNs > 0);
        offsetSeconds += extraSeconds;
    } else {
        const auto extraSeconds = offsetNs / nsPerSecond;

        offsetNs -= (extraSeconds * nsPerSecond);
        BT_ASSERT(offsetNs >= 0);
        offsetSeconds += extraSeconds;
    }

    auto curOffsetSeconds = clkCls.offset().seconds();
    auto curOffsetCycles = clkCls.offset().cycles();

    /* Apply offsets */
    curOffsetSeconds += offsetSeconds;
    curOffsetCycles += cyclesFromNs(clkCls.freq(), offsetNs);

    /* Set final offsets */
    clkCls.offset(ir::ClkOffset {curOffsetSeconds, curOffsetCycles});
}

void MetadataStreamParser::_adjustClkCls(ClkCls& clkCls) noexcept
{
    if (_mClkClsCfg.forceOriginIsUnixEpoch) {
        clkCls.originIsUnixEpoch(true);
    }

    this->_adjustClkClsOffset(clkCls);
}

void MetadataStreamParser::_finalizeTraceCls()
{
    if (!_mTraceCls) {
        /* No trace class yet */
        return;
    }

    /*
     * Set the value saving indexes of dependencies (field classes) and
     * the saved value index of dependent (dynamic-length, optional, and
     * variant) field classes.
     */
    setSavedValIndexes(*_mTraceCls);

    /* Adjust clock classes, if needed */
    for (const auto& dataStreamCls : *_mTraceCls) {
        const auto clkCls = dataStreamCls->defClkCls();

        if (!clkCls) {
            /* Data stream class has no default clock class */
            continue;
        }

        if (_mAdjustedClkClasses.find(clkCls) != _mAdjustedClkClasses.end()) {
            /* Already done */
            continue;
        }

        /* Adjust and normalize */
        this->_adjustClkCls(*clkCls);
        normalizeClkClsOffset(*clkCls);

        /* This one is now done */
        _mAdjustedClkClasses.insert(clkCls);
    }

    /* Translates CTF IR objects to their trace IR equivalents */
    if (_mSelfComp) {
        LibTraceClsFromTraceClsTranslator {*_mTraceCls, *_mSelfComp};
    }
}

} /* namespace src */
} /* namespace ctf */
