/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_ITEM_SEQ_ITEM_HPP
#define _CTF_SRC_ITEM_SEQ_ITEM_HPP

#include <algorithm>
#include <cstdint>
#include <string>

#include "common/assert.h"
#include "cpp-common/bt2s/string-view.hpp"
#include "cpp-common/vendor/fmt/format.h" /* IWYU pragma: keep */

#include "../metadata/ctf-ir.hpp"
#include "item-visitor.hpp"

namespace ctf {
namespace src {

class ItemSeqIter;

/*
 * Abstract item base class.
 *
 * An item is the value of an item sequence iterator.
 */
class Item
{
private:
    /* clang-format off */
    struct _TypeTraits final
    {
        enum
        {
            END                             = 1ULL << 0,
            BEGIN                           = 1ULL << 1,
            PKT                             = 1ULL << 2,
            SCOPE                           = 1ULL << 3,
            PKT_CONTENT                     = 1ULL << 4,
            EVENT_RECORD                    = 1ULL << 5,
            PKT_MAGIC_NUMBER                = 1ULL << 6,
            METADATA_STREAM_UUID            = 1ULL << 7,
            DATA_STREAM                     = 1ULL << 8,
            INFO                            = 1ULL << 9,
            DEF_CLK_VAL                     = 1ULL << 10,
            FIXED_LEN_BIT_ARRAY_FIELD       = 1ULL << 11,
            BOOL_FIELD                      = 1ULL << 12,
            INT_FIELD                       = 1ULL << 13,
            SIGNED                          = 1ULL << 14,
            UNSIGNED                        = 1ULL << 15,
            FLOAT_FIELD                     = 1ULL << 16,
            ENUM_FIELD                      = INT_FIELD | (1ULL << 17),
            VAR_LEN_INT_FIELD               = INT_FIELD | (1ULL << 18),
            NULL_TERMINATED_STR_FIELD       = 1ULL << 19,
            NON_NULL_TERMINATED_STR_FIELD   = 1ULL << 20,
            STR_FIELD_SUBSTR                = 1ULL << 21,
            BLOB_FIELD_SECTION              = 1ULL << 22,
            STRUCT_FIELD                    = 1ULL << 23,
            STATIC_LEN_FIELD                = 1ULL << 24,
            DYN_LEN_FIELD                   = 1ULL << 25,
            ARRAY_FIELD                     = 1ULL << 26,
            BLOB_FIELD                      = 1ULL << 27,
            VARIANT_FIELD                   = 1ULL << 28,
            INT_SEL                         = 1ULL << 29,
            BOOL_SEL                        = 1ULL << 30,
            OPTIONAL_FIELD                  = 1ULL << 31,
        };
    };

public:
    /*
     * Item type.
     */
    enum class Type : unsigned long long
    {
        /* `PktBeginItem` */
        PKT_BEGIN                           = _TypeTraits::PKT | _TypeTraits::BEGIN,

        /* `PktEndItem` */
        PKT_END                             = _TypeTraits::PKT | _TypeTraits::END,

        /* `ScopeBeginItem` */
        SCOPE_BEGIN                         = _TypeTraits::SCOPE | _TypeTraits::BEGIN,

        /* `ScopeEndItem` */
        SCOPE_END                           = _TypeTraits::SCOPE | _TypeTraits::END,

        /* `PktContentBeginItem` */
        PKT_CONTENT_BEGIN                   = _TypeTraits::PKT_CONTENT | _TypeTraits::BEGIN,

        /* `PktContentEndItem` */
        PKT_CONTENT_END                     = _TypeTraits::PKT_CONTENT | _TypeTraits::END,

        /* `EventRecordBeginItem` */
        EVENT_RECORD_BEGIN                  = _TypeTraits::EVENT_RECORD | _TypeTraits::BEGIN,

        /* `EventRecordEndItem` */
        EVENT_RECORD_END                    = _TypeTraits::EVENT_RECORD | _TypeTraits::END,

        /* `PktMagicNumberItem` */
        PKT_MAGIC_NUMBER                    = _TypeTraits::PKT_MAGIC_NUMBER,

        /* `MetadataStreamUuidItem` */
        METADATA_STREAM_UUID                = _TypeTraits::METADATA_STREAM_UUID,

        /* `DataStreamInfoItem` */
        DATA_STREAM_INFO                    = _TypeTraits::DATA_STREAM | _TypeTraits::INFO,

        /* `DefClkValItem` */
        DEF_CLK_VALUE                       = _TypeTraits::DEF_CLK_VAL,

        /* `PktInfoItem` */
        PKT_INFO                            = _TypeTraits::PKT | _TypeTraits::INFO,

        /* `EventRecordInfoItem` */
        EVENT_RECORD_INFO                   = _TypeTraits::EVENT_RECORD | _TypeTraits::INFO,

        /* `FixedLenBitArrayFieldItem` */
        FIXED_LEN_BIT_ARRAY_FIELD           = _TypeTraits::FIXED_LEN_BIT_ARRAY_FIELD,

        /* `FixedLenBoolFieldItem` */
        FIXED_LEN_BOOL_FIELD                = _TypeTraits::FIXED_LEN_BIT_ARRAY_FIELD | _TypeTraits::BOOL_FIELD,

        /* `FixedLenSIntFieldItem` */
        FIXED_LEN_SINT_FIELD                = _TypeTraits::FIXED_LEN_BIT_ARRAY_FIELD | _TypeTraits::INT_FIELD | _TypeTraits::SIGNED,

        /* `FixedLenUIntFieldItem` */
        FIXED_LEN_UINT_FIELD                = _TypeTraits::FIXED_LEN_BIT_ARRAY_FIELD | _TypeTraits::INT_FIELD | _TypeTraits::UNSIGNED,

        /* `FixedLenFloatFieldItem` */
        FIXED_LEN_FLOAT_FIELD               = _TypeTraits::FIXED_LEN_BIT_ARRAY_FIELD | _TypeTraits::FLOAT_FIELD,

        /* `FixedLenSEnumFieldItem` */
        FIXED_LEN_SENUM_FIELD               = _TypeTraits::FIXED_LEN_BIT_ARRAY_FIELD | _TypeTraits::ENUM_FIELD | _TypeTraits::SIGNED,

        /* `FixedLenUEnumFieldItem` */
        FIXED_LEN_UENUM_FIELD               = _TypeTraits::FIXED_LEN_BIT_ARRAY_FIELD | _TypeTraits::ENUM_FIELD | _TypeTraits::UNSIGNED,

        /* `VarLenSIntFieldItem` */
        VAR_LEN_SINT_FIELD                  = _TypeTraits::VAR_LEN_INT_FIELD | _TypeTraits::SIGNED,

        /* `VarLenUIntFieldItem` */
        VAR_LEN_UINT_FIELD                  = _TypeTraits::VAR_LEN_INT_FIELD | _TypeTraits::UNSIGNED,

        /* `VarLenSEnumFieldItem` */
        VAR_LEN_SENUM_FIELD                 = _TypeTraits::VAR_LEN_INT_FIELD | _TypeTraits::ENUM_FIELD | _TypeTraits::SIGNED,

        /* `VarLenUEnumFieldItem` */
        VAR_LEN_UENUM_FIELD                 = _TypeTraits::VAR_LEN_INT_FIELD | _TypeTraits::ENUM_FIELD | _TypeTraits::UNSIGNED,

        /* `NullTerminatedStrFieldBeginItem` */
        NULL_TERMINATED_STR_FIELD_BEGIN     = _TypeTraits::NULL_TERMINATED_STR_FIELD | _TypeTraits::BEGIN,

        /* `NullTerminatedStrFieldEndItem` */
        NULL_TERMINATED_STR_FIELD_END       = _TypeTraits::NULL_TERMINATED_STR_FIELD | _TypeTraits::END,

        /* `StrFieldSubstrItem` */
        STR_FIELD_SUBSTR                    = _TypeTraits::STR_FIELD_SUBSTR,

        /* `BlobFieldSectionItem` */
        BLOB_FIELD_SECTION                  = _TypeTraits::BLOB_FIELD_SECTION,

        /* `StructFieldBeginItem` */
        STRUCT_FIELD_BEGIN                  = _TypeTraits::STRUCT_FIELD | _TypeTraits::BEGIN,

        /* `StructFieldEndItem` */
        STRUCT_FIELD_END                    = _TypeTraits::STRUCT_FIELD | _TypeTraits::END,

        /* `StaticLenArrayFieldBeginItem` */
        STATIC_LEN_ARRAY_FIELD_BEGIN        = _TypeTraits::STATIC_LEN_FIELD | _TypeTraits::ARRAY_FIELD | _TypeTraits::BEGIN,

        /* `StaticLenArrayFieldEndItem` */
        STATIC_LEN_ARRAY_FIELD_END          = _TypeTraits::STATIC_LEN_FIELD | _TypeTraits::ARRAY_FIELD | _TypeTraits::END,

        /* `DynLenArrayFieldBeginItem` */
        DYN_LEN_ARRAY_FIELD_BEGIN           = _TypeTraits::DYN_LEN_FIELD | _TypeTraits::ARRAY_FIELD | _TypeTraits::BEGIN,

        /* `DynLenArrayFieldEndItem` */
        DYN_LEN_ARRAY_FIELD_END             = _TypeTraits::DYN_LEN_FIELD | _TypeTraits::ARRAY_FIELD | _TypeTraits::END,

        /* `StaticLenBlobFieldBeginItem` */
        STATIC_LEN_BLOB_FIELD_BEGIN         = _TypeTraits::STATIC_LEN_FIELD | _TypeTraits::BLOB_FIELD | _TypeTraits::BEGIN,

        /* `StaticLenBlobFieldEndItem` */
        STATIC_LEN_BLOB_FIELD_END           = _TypeTraits::STATIC_LEN_FIELD | _TypeTraits::BLOB_FIELD | _TypeTraits::END,

        /* `DynLenBlobFieldBeginItem` */
        DYN_LEN_BLOB_FIELD_BEGIN            = _TypeTraits::DYN_LEN_FIELD | _TypeTraits::BLOB_FIELD | _TypeTraits::BEGIN,

        /* `DynLenBlobFieldEndItem` */
        DYN_LEN_BLOB_FIELD_END              = _TypeTraits::DYN_LEN_FIELD | _TypeTraits::BLOB_FIELD | _TypeTraits::END,

        /* `StaticLenStrFieldBeginItem` */
        STATIC_LEN_STR_FIELD_BEGIN         = _TypeTraits::STATIC_LEN_FIELD | _TypeTraits::NON_NULL_TERMINATED_STR_FIELD | _TypeTraits::BEGIN,

        /* `StaticLenStrFieldEndItem` */
        STATIC_LEN_STR_FIELD_END           = _TypeTraits::STATIC_LEN_FIELD | _TypeTraits::NON_NULL_TERMINATED_STR_FIELD | _TypeTraits::END,

        /* `DynLenStrFieldBeginItem` */
        DYN_LEN_STR_FIELD_BEGIN            = _TypeTraits::DYN_LEN_FIELD | _TypeTraits::NON_NULL_TERMINATED_STR_FIELD | _TypeTraits::BEGIN,

        /* `DynLenStrFieldEndItem` */
        DYN_LEN_STR_FIELD_END              = _TypeTraits::DYN_LEN_FIELD | _TypeTraits::NON_NULL_TERMINATED_STR_FIELD | _TypeTraits::END,

        /* `VariantFieldWithSIntSelBeginItem` */
        VARIANT_FIELD_WITH_SINT_SEL_BEGIN   = _TypeTraits::VARIANT_FIELD | _TypeTraits::SIGNED | _TypeTraits::BEGIN,

        /* `VariantFieldWithSIntSelEndItem` */
        VARIANT_FIELD_WITH_SINT_SEL_END     = _TypeTraits::VARIANT_FIELD | _TypeTraits::SIGNED | _TypeTraits::END,

        /* `VariantFieldWithUIntSelBeginItem` */
        VARIANT_FIELD_WITH_UINT_SEL_BEGIN   = _TypeTraits::VARIANT_FIELD | _TypeTraits::UNSIGNED | _TypeTraits::BEGIN,

        /* `VariantFieldWithUIntSelEndItem` */
        VARIANT_FIELD_WITH_UINT_SEL_END     = _TypeTraits::VARIANT_FIELD | _TypeTraits::UNSIGNED | _TypeTraits::END,

        /* `OptionalFieldWithBoolSelBeginItem` */
        OPTIONAL_FIELD_WITH_BOOL_SEL_BEGIN  = _TypeTraits::OPTIONAL_FIELD | _TypeTraits::BOOL_SEL | _TypeTraits::BEGIN,

        /* `OptionalFieldWithBoolSelEndItem` */
        OPTIONAL_FIELD_WITH_BOOL_SEL_END    = _TypeTraits::OPTIONAL_FIELD | _TypeTraits::BOOL_SEL | _TypeTraits::END,

        /* `OptionalFieldWithSIntSelBeginItem` */
        OPTIONAL_FIELD_WITH_SINT_SEL_BEGIN  = _TypeTraits::OPTIONAL_FIELD | _TypeTraits::SIGNED | _TypeTraits::BEGIN,

        /* `OptionalFieldWithSIntSelEndItem` */
        OPTIONAL_FIELD_WITH_SINT_SEL_END    = _TypeTraits::OPTIONAL_FIELD | _TypeTraits::SIGNED | _TypeTraits::END,

        /* `OptionalFieldWithUIntSelBeginItem` */
        OPTIONAL_FIELD_WITH_UINT_SEL_BEGIN  = _TypeTraits::OPTIONAL_FIELD | _TypeTraits::UNSIGNED | _TypeTraits::BEGIN,

        /* `OptionalFieldWithUIntSelEndItem` */
        OPTIONAL_FIELD_WITH_UINT_SEL_END    = _TypeTraits::OPTIONAL_FIELD | _TypeTraits::UNSIGNED | _TypeTraits::END,
    };
    /* clang-format on */

protected:
    explicit Item(Type type) noexcept;

public:
    virtual ~Item() = default;

    /*
     * Type of this item.
     *
     * You can also use accept() with an `ItemVisitor` instance to get
     * access to the concrete item.
     */
    Type type() const noexcept
    {
        return _mType;
    }

    virtual void accept(ItemVisitor& visitor) const = 0;

    /*
     * True if this item is a beginning item.
     */
    bool isBeginItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::BEGIN);
    }

    /*
     * True if this item is an end item.
     */
    bool isEndItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::END);
    }

    /*
     * True if this item is a packet beginning/end item.
     */
    bool isPktItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::PKT);
    }

    /*
     * True if this item is a packet beginning item.
     */
    bool isPktBeginItem() const noexcept
    {
        return _mType == Type::PKT_BEGIN;
    }

    /*
     * True if this item is a packet end item.
     */
    bool isPktEndItem() const noexcept
    {
        return _mType == Type::PKT_END;
    }

    /*
     * True if this item is a scope beginning/end item.
     */
    bool isScopeItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::SCOPE);
    }

    /*
     * True if this item is a scope beginning item.
     */
    bool isScopeBeginItem() const noexcept
    {
        return _mType == Type::SCOPE_BEGIN;
    }

    /*
     * True if this item is a scope end item.
     */
    bool isScopeEndItem() const noexcept
    {
        return _mType == Type::SCOPE_END;
    }

    /*
     * True if this item is a packet content beginning/end item.
     */
    bool isPktContentItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::PKT_CONTENT);
    }

    /*
     * True if this item is a packet content beginning item.
     */
    bool isPktContentBeginItem() const noexcept
    {
        return _mType == Type::PKT_CONTENT_BEGIN;
    }

    /*
     * True if this item is a packet content end item.
     */
    bool isPktContentEndItem() const noexcept
    {
        return _mType == Type::PKT_CONTENT_END;
    }

    /*
     * True if this item is an event record beginning/end item.
     */
    bool isEventRecordItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::EVENT_RECORD);
    }

    /*
     * True if this item is an event record beginning item.
     */
    bool isEventRecordBeginItem() const noexcept
    {
        return _mType == Type::EVENT_RECORD_BEGIN;
    }

    /*
     * True if this item is an event record end item.
     */
    bool isEventRecordEndItem() const noexcept
    {
        return _mType == Type::EVENT_RECORD_END;
    }

    /*
     * True if this item is a packet magic number item.
     */
    bool isPktMagicNumberItem() const noexcept
    {
        return _mType == Type::PKT_MAGIC_NUMBER;
    }

    /*
     * True if this item is a metadata stream UUID item.
     */
    bool isMetadataStreamUuidItem() const noexcept
    {
        return _mType == Type::METADATA_STREAM_UUID;
    }

    /*
     * True if this item is a data stream info item.
     */
    bool isDataStreamInfoItem() const noexcept
    {
        return _mType == Type::DATA_STREAM_INFO;
    }

    /*
     * True if this item is a default clock value item.
     */
    bool isDefClkValItem() const noexcept
    {
        return _mType == Type::DEF_CLK_VALUE;
    }

    /*
     * True if this item is an info item.
     */
    bool isInfoItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::INFO);
    }

    /*
     * True if this item is a packet info item.
     */
    bool isPktInfoItem() const noexcept
    {
        return _mType == Type::PKT_INFO;
    }

    /*
     * True if this item is an event record info item.
     */
    bool isEventRecordInfoItem() const noexcept
    {
        return _mType == Type::EVENT_RECORD_INFO;
    }

    /*
     * True if this item is a fixed-length bit array field item.
     */
    bool isFixedLenBitArrayFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::FIXED_LEN_BIT_ARRAY_FIELD);
    }

    /*
     * True if this item is a fixed-length boolean field item.
     */
    bool isFixedLenBoolFieldItem() const noexcept
    {
        return _mType == Type::FIXED_LEN_BOOL_FIELD;
    }

    /*
     * True if this item is an integer field item.
     */
    bool isIntFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::INT_FIELD);
    }

    /*
     * True if this item is a fixed-length integer field item.
     */
    bool isFixedLenIntegerFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::FIXED_LEN_BIT_ARRAY_FIELD | _TypeTraits::INT_FIELD);
    }

    /*
     * True if this item is a signed integer field item.
     */
    bool isSIntFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::INT_FIELD | _TypeTraits::SIGNED);
    }

    /*
     * True if this item is an unsigned integer field item.
     */
    bool isUIntFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::INT_FIELD | _TypeTraits::UNSIGNED);
    }

    /*
     * True if this item is a fixed-length signed integer field item.
     */
    bool isFixedLenSIntFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::FIXED_LEN_BIT_ARRAY_FIELD | _TypeTraits::INT_FIELD |
                                   _TypeTraits::SIGNED);
    }

    /*
     * True if this item is a fixed-length unsigned integer field item.
     */
    bool isFixedLenUIntFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::FIXED_LEN_BIT_ARRAY_FIELD | _TypeTraits::INT_FIELD |
                                   _TypeTraits::UNSIGNED);
    }

    /*
     * True if this item is a fixed-length floating-point number field
     * item.
     */
    bool isFixedLenFloatFieldItem() const noexcept
    {
        return _mType == Type::FIXED_LEN_FLOAT_FIELD;
    }

    /*
     * True if this item is an enumeration field item.
     */
    bool isEnumFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::ENUM_FIELD);
    }

    /*
     * True if this item is a fixed-length enumeration field item.
     */
    bool isFixedLenEnumerationFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::FIXED_LEN_BIT_ARRAY_FIELD |
                                   _TypeTraits::ENUM_FIELD);
    }

    /*
     * True if this item is a signed enumeration field item.
     */
    bool isSEnumFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::ENUM_FIELD | _TypeTraits::SIGNED);
    }

    /*
     * True if this item is an unsigned enumeration field item.
     */
    bool isUEnumFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::ENUM_FIELD | _TypeTraits::UNSIGNED);
    }

    /*
     * True if this item is a fixed-length signed enumeration field
     * item.
     */
    bool isFixedLenSEnumFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::FIXED_LEN_BIT_ARRAY_FIELD |
                                   _TypeTraits::ENUM_FIELD | _TypeTraits::SIGNED);
    }

    /*
     * True if this item is a fixed-length unsigned enumeration field
     * item.
     */
    bool isFixedLenUEnumFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::FIXED_LEN_BIT_ARRAY_FIELD |
                                   _TypeTraits::ENUM_FIELD | _TypeTraits::UNSIGNED);
    }

    /*
     * True if this item is a variable-length integer field item.
     */
    bool isVarLenIntFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::VAR_LEN_INT_FIELD);
    }

    /*
     * True if this item is a variable-length signed integer field item.
     */
    bool isVarLenSIntFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::VAR_LEN_INT_FIELD | _TypeTraits::SIGNED);
    }

    /*
     * True if this item is a variable-length unsigned integer field
     * item.
     */
    bool isVarLenUIntFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::VAR_LEN_INT_FIELD | _TypeTraits::UNSIGNED);
    }

    /*
     * True if this item is a variable-length enumeration field item.
     */
    bool isVarLenEnumFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::VAR_LEN_INT_FIELD | _TypeTraits::ENUM_FIELD);
    }

    /*
     * True if this item is a variable-length signed enumeration field
     * item.
     */
    bool isVarLenSEnumFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::VAR_LEN_INT_FIELD | _TypeTraits::ENUM_FIELD |
                                   _TypeTraits::SIGNED);
    }

    /*
     * True if this item is a variable-length unsigned enumeration field
     * item.
     */
    bool isVarLenUEnumFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::VAR_LEN_INT_FIELD | _TypeTraits::ENUM_FIELD |
                                   _TypeTraits::UNSIGNED);
    }

    /*
     * True if this item is a null-terminated string field beginning/end
     * item.
     */
    bool isNullTerminatedStrFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::NULL_TERMINATED_STR_FIELD);
    }

    /*
     * True if this item is a null-terminated string field beginning
     * item.
     */
    bool isNullTerminatedStrFieldBeginItem() const noexcept
    {
        return _mType == Type::NULL_TERMINATED_STR_FIELD_BEGIN;
    }

    /*
     * True if this item is a null-terminated string field end item.
     */
    bool isNullTerminatedStrFieldEndItem() const noexcept
    {
        return _mType == Type::NULL_TERMINATED_STR_FIELD_END;
    }

    /*
     * True if this item is a string field substring item.
     */
    bool isStrFieldSubstrItem() const noexcept
    {
        return _mType == Type::STR_FIELD_SUBSTR;
    }

    /*
     * True if this item is a BLOB field section item.
     */
    bool isBlobFieldSectionItem() const noexcept
    {
        return _mType == Type::BLOB_FIELD_SECTION;
    }

    /*
     * True if this item is a structure field beginning/end item.
     */
    bool isStructFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::STRUCT_FIELD);
    }

    /*
     * True if this item is a structure field beginning item.
     */
    bool isStructFieldBeginItem() const noexcept
    {
        return _mType == Type::STRUCT_FIELD_BEGIN;
    }

    /*
     * True if this item is a structure field end item.
     */
    bool isStructFieldEndItem() const noexcept
    {
        return _mType == Type::STRUCT_FIELD_END;
    }

    /*
     * True if this item is an array field beginning/end item.
     */
    bool isArrayItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::ARRAY_FIELD);
    }

    /*
     * True if this item is a static-length array field beginning/end
     * item.
     */
    bool isStaticLenArrayItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::STATIC_LEN_FIELD | _TypeTraits::ARRAY_FIELD);
    }

    /*
     * True if this item is a static-length array field beginning item.
     */
    bool isStaticLenArrayFieldBeginItem() const noexcept
    {
        return _mType == Type::STATIC_LEN_ARRAY_FIELD_BEGIN;
    }

    /*
     * True if this item is a static-length array field end item.
     */
    bool isStaticLenArrayFieldEndItem() const noexcept
    {
        return _mType == Type::STATIC_LEN_ARRAY_FIELD_END;
    }

    /*
     * True if this item is a dynamic-length array field beginning/end
     * item.
     */
    bool isDynLenArrayItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::DYN_LEN_FIELD | _TypeTraits::ARRAY_FIELD);
    }

    /*
     * True if this item is a dynamic-length array field beginning item.
     */
    bool isDynLenArrayFieldBeginItem() const noexcept
    {
        return _mType == Type::DYN_LEN_ARRAY_FIELD_BEGIN;
    }

    /*
     * True if this item is a dynamic-length array field end item.
     */
    bool isDynLenArrayFieldEndItem() const noexcept
    {
        return _mType == Type::DYN_LEN_ARRAY_FIELD_END;
    }

    /*
     * True if this item is a non-null-terminated field beginning/end
     * item.
     */
    bool isNonNullTerminatedStrFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::NON_NULL_TERMINATED_STR_FIELD);
    }

    /*
     * True if this item is a static-length string field beginning/end
     * item.
     */
    bool isStaticLenStrFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::STATIC_LEN_FIELD |
                                   _TypeTraits::NON_NULL_TERMINATED_STR_FIELD);
    }

    /*
     * True if this item is a static-length string field beginning item.
     */
    bool isStaticLenStrFieldBeginItem() const noexcept
    {
        return _mType == Type::STATIC_LEN_STR_FIELD_BEGIN;
    }

    /*
     * True if this item is a static-length string field end item.
     */
    bool isStaticLenStrFieldEndItem() const noexcept
    {
        return _mType == Type::STATIC_LEN_STR_FIELD_END;
    }

    /*
     * True if this item is a dynamic-length string field beginning/end
     * item.
     */
    bool isDynLenStrFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::DYN_LEN_FIELD |
                                   _TypeTraits::NON_NULL_TERMINATED_STR_FIELD);
    }

    /*
     * True if this item is a dynamic-length string field beginning
     * item.
     */
    bool isDynLenStrFieldBeginItem() const noexcept
    {
        return _mType == Type::DYN_LEN_STR_FIELD_BEGIN;
    }

    /*
     * True if this item is a dynamic-length string field end item.
     */
    bool isDynLenStrFieldEndItem() const noexcept
    {
        return _mType == Type::DYN_LEN_STR_FIELD_END;
    }

    /*
     * True if this item is a BLOB field beginning/end item.
     */
    bool isBlobFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::BLOB_FIELD);
    }

    /*
     * True if this item is a static-length BLOB field beginning/end
     * item.
     */
    bool isStaticLenBlobFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::STATIC_LEN_FIELD | _TypeTraits::BLOB_FIELD);
    }

    /*
     * True if this item is a static-length BLOB field beginning item.
     */
    bool isStaticLenBlobFieldBeginItem() const noexcept
    {
        return _mType == Type::STATIC_LEN_BLOB_FIELD_BEGIN;
    }

    /*
     * True if this item is a static-length BLOB field end item.
     */
    bool isStaticLenBlobFieldEndItem() const noexcept
    {
        return _mType == Type::STATIC_LEN_BLOB_FIELD_END;
    }

    /*
     * True if this item is a dynamic-length BLOB field beginning/end
     * item.
     */
    bool isDynLenBlobFieldItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::DYN_LEN_FIELD | _TypeTraits::BLOB_FIELD);
    }

    /*
     * True if this item is a dynamic-length BLOB field beginning item.
     */
    bool isDynLenBlobFieldBeginItem() const noexcept
    {
        return _mType == Type::DYN_LEN_BLOB_FIELD_BEGIN;
    }

    /*
     * True if this item is a dynamic-length BLOB field end item.
     */
    bool isDynLenBlobFieldEndItem() const noexcept
    {
        return _mType == Type::DYN_LEN_BLOB_FIELD_END;
    }

    /*
     * True if this item is a variant field beginning/end item.
     */
    bool isVariantItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::VARIANT_FIELD);
    }

    /*
     * True if this item is a variant field beginning item.
     */
    bool isVariantFieldBeginItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::VARIANT_FIELD | _TypeTraits::BEGIN);
    }

    /*
     * True if this item is a variant field end item.
     */
    bool isVariantFieldEndItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::VARIANT_FIELD | _TypeTraits::END);
    }

    /*
     * True if this item is a variant field with a signed integer
     * selector beginning/end item.
     */
    bool isVariantWithSIntSelItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::VARIANT_FIELD | _TypeTraits::SIGNED);
    }

    /*
     * True if this item is a variant field with a signed integer
     * selector beginning item.
     */
    bool isVariantFieldWithSIntSelBeginItem() const noexcept
    {
        return _mType == Type::VARIANT_FIELD_WITH_SINT_SEL_BEGIN;
    }

    /*
     * True if this item is a variant field with a signed integer
     * selector end item.
     */
    bool isVariantFieldWithSIntSelEndItem() const noexcept
    {
        return _mType == Type::VARIANT_FIELD_WITH_SINT_SEL_END;
    }

    /*
     * True if this item is a variant field with an unsigned integer
     * selector beginning/end item.
     */
    bool isVariantWithUIntSelItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::VARIANT_FIELD | _TypeTraits::UNSIGNED);
    }

    /*
     * True if this item is a variant field with an unsigned integer
     * selector beginning item.
     */
    bool isVariantFieldWithUIntSelBeginItem() const noexcept
    {
        return _mType == Type::VARIANT_FIELD_WITH_UINT_SEL_BEGIN;
    }

    /*
     * True if this item is a variant field with an unsigned integer
     * selector end item.
     */
    bool isVariantFieldWithUIntSelEndItem() const noexcept
    {
        return _mType == Type::VARIANT_FIELD_WITH_UINT_SEL_END;
    }

    /*
     * True if this item is an optional field beginning/end item.
     */
    bool isOptionalItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::OPTIONAL_FIELD);
    }

    /*
     * True if this item is an optional field beginning item.
     */
    bool isOptionalFieldBeginItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::OPTIONAL_FIELD | _TypeTraits::BEGIN);
    }

    /*
     * True if this item is an optional field end item.
     */
    bool isOptionalFieldEndItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::OPTIONAL_FIELD | _TypeTraits::END);
    }

    /*
     * True if this item is an optional field with a boolean selector
     * beginning/end item.
     */
    bool isOptionalWithBoolSelItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::OPTIONAL_FIELD | _TypeTraits::BOOL_SEL);
    }

    /*
     * True if this item is an optional field with a boolean selector
     * beginning item.
     */
    bool isOptionalFieldWithBoolSelBeginItem() const noexcept
    {
        return _mType == Type::OPTIONAL_FIELD_WITH_BOOL_SEL_BEGIN;
    }

    /*
     * True if this item is an optional field with a boolean selector
     * end item.
     */
    bool isOptionalFieldWithBoolSelEndItem() const noexcept
    {
        return _mType == Type::OPTIONAL_FIELD_WITH_BOOL_SEL_END;
    }

    /*
     * True if this item is an optional field with an integer selector
     * beginning/end item.
     */
    bool isOptionalWithIntegerSelItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::OPTIONAL_FIELD | _TypeTraits::SIGNED |
                                   _TypeTraits::UNSIGNED);
    }

    /*
     * True if this item is an optional field with an integer selector
     * beginning item.
     */
    bool isOptionalFieldWithIntSelBeginItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::OPTIONAL_FIELD | _TypeTraits::SIGNED |
                                   _TypeTraits::UNSIGNED | _TypeTraits::BEGIN);
    }

    /*
     * True if this item is an optional field with an integer selector
     * end item.
     */
    bool isOptionalFieldWithIntSelEndItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::OPTIONAL_FIELD | _TypeTraits::SIGNED |
                                   _TypeTraits::UNSIGNED | _TypeTraits::END);
    }

    /*
     * True if this item is an optional field with a signed integer
     * selector beginning/end item.
     */
    bool isOptionalWithSIntSelItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::OPTIONAL_FIELD | _TypeTraits::SIGNED);
    }

    /*
     * True if this item is an optional field with a signed integer
     * selector beginning item.
     */
    bool isOptionalFieldWithSIntSelBeginItem() const noexcept
    {
        return _mType == Type::OPTIONAL_FIELD_WITH_SINT_SEL_BEGIN;
    }

    /*
     * True if this item is an optional field with a signed integer
     * selector end item.
     */
    bool isOptionalFieldWithSIntSelEndItem() const noexcept
    {
        return _mType == Type::OPTIONAL_FIELD_WITH_SINT_SEL_END;
    }

    /*
     * True if this item is an optional field with an unsigned integer
     * selector beginning/end item.
     */
    bool isOptionalWithUIntSelItem() const noexcept
    {
        return this->_hasTypeTrait(_TypeTraits::OPTIONAL_FIELD | _TypeTraits::UNSIGNED);
    }

    /*
     * True if this item is an optional field with an unsigned integer
     * selector beginning item.
     */
    bool isOptionalFieldWithUIntSelBeginItem() const noexcept
    {
        return _mType == Type::OPTIONAL_FIELD_WITH_UINT_SEL_BEGIN;
    }

    /*
     * True if this item is an optional field with an unsigned integer
     * selector end item.
     */
    bool isOptionalFieldWithUIntSelEndItem() const noexcept
    {
        return _mType == Type::OPTIONAL_FIELD_WITH_UINT_SEL_END;
    }

    /*
     * Returns this item as a BLOB field section item.
     */
    const BlobFieldSectionItem& asBlobFieldSectionItem() const noexcept;

    /*
     * Returns this item as a data stream info item.
     */
    const DataStreamInfoItem& asDataStreamInfoItem() const noexcept;

    /*
     * Returns this item as a default clock value item.
     */
    const DefClkValItem& asDefClkValItem() const noexcept;

    /*
     * Returns this item as a dynamic-length array field beginning item.
     */
    const DynLenArrayFieldBeginItem& asDynLenArrayFieldBeginItem() const noexcept;

    /*
     * Returns this item as a dynamic-length array field end item.
     */
    const DynLenArrayFieldEndItem& asDynLenArrayFieldEndItem() const noexcept;

    /*
     * Returns this item as a dynamic-length string field beginning item.
     */
    const DynLenStrFieldBeginItem& asDynLenStrFieldBeginItem() const noexcept;

    /*
     * Returns this item as a dynamic-length string field end item.
     */
    const DynLenStrFieldEndItem& asDynLenStrFieldEndItem() const noexcept;

    /*
     * Returns this item as a dynamic-length BLOB field beginning item.
     */
    const DynLenBlobFieldBeginItem& asDynLenBlobFieldBeginItem() const noexcept;

    /*
     * Returns this item as a dynamic-length BLOB field end item.
     */
    const DynLenBlobFieldEndItem& asDynLenBlobFieldEndItem() const noexcept;

    /*
     * Returns this item as an event record beginning item.
     */
    const EventRecordBeginItem& asEventRecordBeginItem() const noexcept;

    /*
     * Returns this item as an event record end item.
     */
    const EventRecordEndItem& asEventRecordEndItem() const noexcept;

    /*
     * Returns this item as an event record info item.
     */
    const EventRecordInfoItem& asEventRecordInfoItem() const noexcept;

    /*
     * Returns this item as a fixed-length bit array field item.
     */
    const FixedLenBitArrayFieldItem& asFixedLenBitArrayFieldItem() const noexcept;

    /*
     * Returns this item as a fixed-length boolean field item.
     */
    const FixedLenBoolFieldItem& asFixedLenBoolFieldItem() const noexcept;

    /*
     * Returns this item as a fixed-length floating-point number field
     * item.
     */
    const FixedLenFloatFieldItem& asFixedLenFloatFieldItem() const noexcept;

    /*
     * Returns this item as a fixed-length signed enumeration field
     * item.
     */
    const FixedLenSEnumFieldItem& asFixedLenSEnumFieldItem() const noexcept;

    /*
     * Returns this item as a fixed-length signed integer field item.
     */
    const FixedLenSIntFieldItem& asFixedLenSIntFieldItem() const noexcept;

    /*
     * Returns this item as a fixed-length unsigned enumeration field
     * item.
     */
    const FixedLenUEnumFieldItem& asFixedLenUEnumFieldItem() const noexcept;

    /*
     * Returns this item as a fixed-length unsigned integer field item.
     */
    const FixedLenUIntFieldItem& asFixedLenUIntFieldItem() const noexcept;

    /*
     * Returns this item as a string field beginning item.
     */
    const NullTerminatedStrFieldBeginItem& asNullTerminatedStrFieldBeginItem() const noexcept;

    /*
     * Returns this item as a string field end item.
     */
    const NullTerminatedStrFieldEndItem& asNullTerminatedStrFieldEndItem() const noexcept;

    /*
     * Returns this item as an optional field beginning item.
     */
    const OptionalFieldBeginItem& asOptionalFieldBeginItem() const noexcept;

    /*
     * Returns this item as an optional field end item.
     */
    const OptionalFieldEndItem& asOptionalFieldEndItem() const noexcept;

    /*
     * Returns this item as an optional field with a boolean selector
     * beginning item.
     */
    const OptionalFieldWithBoolSelBeginItem& asOptionalFieldWithBoolSelBeginItem() const noexcept;

    /*
     * Returns this item as an optional field with a boolean selector
     * end item.
     */
    const OptionalFieldWithBoolSelEndItem& asOptionalFieldWithBoolSelEndItem() const noexcept;

    /*
     * Returns this item as an optional field with a signed integer
     * selector beginning item.
     */
    const OptionalFieldWithSIntSelBeginItem& asOptionalFieldWithSIntSelBeginItem() const noexcept;

    /*
     * Returns this item as an optional field with a signed integer
     * selector end item.
     */
    const OptionalFieldWithSIntSelEndItem& asOptionalFieldWithSIntSelEndItem() const noexcept;

    /*
     * Returns this item as an optional field with an unsigned integer
     * selector beginning item.
     */
    const OptionalFieldWithUIntSelBeginItem& asOptionalFieldWithUIntSelBeginItem() const noexcept;

    /*
     * Returns this item as an optional field with an unsigned integer
     * selector end item.
     */
    const OptionalFieldWithUIntSelEndItem& asOptionalFieldWithUIntSelEndItem() const noexcept;

    /*
     * Returns this item as a packet beginning item.
     */
    const PktBeginItem& asPktBeginItem() const noexcept;

    /*
     * Returns this item as a packet content beginning item.
     */
    const PktContentBeginItem& asPktContentBeginItem() const noexcept;

    /*
     * Returns this item as a packet content end item.
     */
    const PktContentEndItem& asPktContentEndItem() const noexcept;

    /*
     * Returns this item as a packet end item.
     */
    const PktEndItem& asPktEndItem() const noexcept;

    /*
     * Returns this item as a packet info item.
     */
    const PktInfoItem& asPktInfoItem() const noexcept;

    /*
     * Returns this item as a packet magic number item.
     */
    const PktMagicNumberItem& asPktMagicNumberItem() const noexcept;

    /*
     * Returns this item as a scope beginning item.
     */
    const ScopeBeginItem& asScopeBeginItem() const noexcept;

    /*
     * Returns this item as a scope end item.
     */
    const ScopeEndItem& asScopeEndItem() const noexcept;

    /*
     * Returns this item as a static-length array field beginning item.
     */
    const StaticLenArrayFieldBeginItem& asStaticLenArrayFieldBeginItem() const noexcept;

    /*
     * Returns this item as a static-length array field end item.
     */
    const StaticLenArrayFieldEndItem& asStaticLenArrayFieldEndItem() const noexcept;

    /*
     * Returns this item as a static-length string field beginning item.
     */
    const StaticLenStrFieldBeginItem& asStaticLenStrFieldBeginItem() const noexcept;

    /*
     * Returns this item as a static-length string field end item.
     */
    const StaticLenStrFieldEndItem& asStaticLenStrFieldEndItem() const noexcept;

    /*
     * Returns this item as a static-length BLOB field beginning item.
     */
    const StaticLenBlobFieldBeginItem& asStaticLenBlobFieldBeginItem() const noexcept;

    /*
     * Returns this item as a static-length BLOB field end item.
     */
    const StaticLenBlobFieldEndItem& asStaticLenBlobFieldEndItem() const noexcept;

    /*
     * Returns this item as a structure field beginning item.
     */
    const StructFieldBeginItem& asStructFieldBeginItem() const noexcept;

    /*
     * Returns this item as a structure field end item.
     */
    const StructFieldEndItem& asStructFieldEndItem() const noexcept;

    /*
     * Returns this item as a string field substring item.
     */
    const StrFieldSubstrItem& asStrFieldSubstrItem() const noexcept;

    /*
     * Returns this item as a metadata stream UUID item.
     */
    const MetadataStreamUuidItem& asMetadataStreamUuidItem() const noexcept;

    /*
     * Returns this item as a variable-length signed enumeration field
     * item.
     */
    const VarLenSEnumFieldItem& asVarLenSEnumFieldItem() const noexcept;

    /*
     * Returns this item as a variable-length signed integer field item.
     */
    const VarLenSIntFieldItem& asVarLenSIntFieldItem() const noexcept;

    /*
     * Returns this item as a variable-length unsigned enumeration field
     * item.
     */
    const VarLenUEnumFieldItem& asVarLenUEnumFieldItem() const noexcept;

    /*
     * Returns this item as a variable-length unsigned integer field
     * item.
     */
    const VarLenUIntFieldItem& asVarLenUIntFieldItem() const noexcept;

    /*
     * Returns this item as a variant field beginning item.
     */
    const VariantFieldBeginItem& asVariantFieldBeginItem() const noexcept;

    /*
     * Returns this item as a variant field end item.
     */
    const VariantFieldEndItem& asVariantFieldEndItem() const noexcept;

    /*
     * Returns this item as a variant field with a signed integer
     * selector beginning item.
     */
    const VariantFieldWithSIntSelBeginItem& asVariantFieldWithSIntSelBeginItem() const noexcept;

    /*
     * Returns this item as a variant field with a signed integer
     * selector end item.
     */
    const VariantFieldWithSIntSelEndItem& asVariantFieldWithSIntSelEndItem() const noexcept;

    /*
     * Returns this item as a variant field with an unsigned integer
     * selector beginning item.
     */
    const VariantFieldWithUIntSelBeginItem& asVariantFieldWithUIntSelBeginItem() const noexcept;

    /*
     * Returns this item as a variant field with an unsigned integer
     * selector end item.
     */
    const VariantFieldWithUIntSelEndItem& asVariantFieldWithUIntSelEndItem() const noexcept;

private:
    bool _hasTypeTrait(const unsigned long long typeTrait) const noexcept
    {
        return (static_cast<unsigned long long>(_mType) & typeTrait) == typeTrait;
    }

private:
    Type _mType;
};

/*
 * Abstract beginning item base class.
 */
class BeginItem : public Item
{
protected:
    explicit BeginItem(Type type) noexcept;
};

/*
 * Abstract end item base class.
 */
class EndItem : public Item
{
protected:
    explicit EndItem(Type type) noexcept;
};

/*
 * Packet beginning item.
 */
class PktBeginItem final : public BeginItem
{
    friend class ItemSeqIter;

private:
    explicit PktBeginItem() noexcept;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Packet end item.
 */
class PktEndItem final : public EndItem
{
    friend class ItemSeqIter;

private:
    explicit PktEndItem() noexcept;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Abstract scope item base class.
 */
class ScopeItem
{
    friend class ItemSeqIter;

protected:
    explicit ScopeItem() noexcept = default;

public:
    ir::FieldLocScope scope() const noexcept
    {
        return _mScope;
    }

private:
    ir::FieldLocScope _mScope;
};

/*
 * Scope beginning item.
 */
class ScopeBeginItem final : public BeginItem, public ScopeItem
{
    friend class ItemSeqIter;

private:
    explicit ScopeBeginItem() noexcept;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Scope end item.
 */
class ScopeEndItem final : public EndItem, public ScopeItem
{
    friend class ItemSeqIter;

private:
    explicit ScopeEndItem() noexcept;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Event record beginning item.
 */
class EventRecordBeginItem final : public BeginItem
{
    friend class ItemSeqIter;

private:
    explicit EventRecordBeginItem() noexcept;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Event record end item.
 */
class EventRecordEndItem final : public EndItem
{
    friend class ItemSeqIter;

private:
    explicit EventRecordEndItem() noexcept;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Packet content beginning item.
 *
 * Such an item indicates the beginning of the _content_ of the current
 * packet.
 *
 * All the items between this one and the following `PktContentEndItem`
 * within a given item sequence are part of the packet content, which
 * does _not_ include the optional padding bits before the end of the
 * packet (indicated by the next `PktEndItem`).
 */
class PktContentBeginItem final : public BeginItem
{
    friend class ItemSeqIter;

private:
    explicit PktContentBeginItem() noexcept;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Packet content end item.
 *
 * This item indicates the end of the _content_ of the current packet.
 */
class PktContentEndItem final : public EndItem
{
    friend class ItemSeqIter;

private:
    explicit PktContentEndItem() noexcept;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Packet magic number item.
 *
 * This item contains the magic number of the decoded packet, as well as
 * the expected magic number (always 0xc1fc1fc1).
 *
 * Call isValid() to get whether or not the decoded magic number is
 * valid as per the CTF specification.
 */
class PktMagicNumberItem final : public Item
{
    friend class ItemSeqIter;

private:
    explicit PktMagicNumberItem() noexcept;

public:
    void accept(ItemVisitor& visitor) const override;

    /*
     * True if the decoded magic number is valid.
     */
    bool isValid() const noexcept
    {
        return _mVal == this->expectedVal();
    }

    /*
     * Decoded magic number value.
     */
    unsigned long long val() const noexcept
    {
        return _mVal;
    }

    /*
     * Expected magic number value.
     */
    static constexpr unsigned long long expectedVal() noexcept
    {
        return 0xc1fc1fc1;
    }

private:
    unsigned long long _mVal = 0;
};

/*
 * Metadata stream UUID item.
 *
 * This item contains the decoded metadata stream UUID.
 */
class MetadataStreamUuidItem final : public Item
{
    friend class ItemSeqIter;

private:
    explicit MetadataStreamUuidItem() noexcept;

public:
    void accept(ItemVisitor& visitor) const override;

    /*
     * Decoded UUID.
     */
    const bt2c::Uuid& uuid() const noexcept
    {
        return _mUuid;
    }

private:
    bt2c::Uuid _mUuid;
};

/*
 * Data stream information item.
 *
 * This item contains information about the current data stream, as
 * found in the header (if any) of the current packet.
 */
class DataStreamInfoItem final : public Item
{
    friend class ItemSeqIter;

private:
    explicit DataStreamInfoItem() noexcept;

public:
    void accept(ItemVisitor& visitor) const override;

    /*
     * Class of the data stream of the current packet, or `nullptr` if
     * the trace class has no data stream classes.
     */
    const DataStreamCls *cls() const noexcept
    {
        return _mCls;
    }

    /*
     * ID of the data stream of the current packet.
     *
     * NOTE: Not to be confused with the _class_ ID of the data stream
     * of the current packet: use `cls().id()`.
     */
    const bt2s::optional<unsigned long long>& id() const noexcept
    {
        return _mId;
    }

private:
    void _reset() noexcept
    {
        _mCls = nullptr;
        _mId = bt2s::nullopt;
    }

    const DataStreamCls *_mCls = nullptr;
    bt2s::optional<unsigned long long> _mId;
};

/*
 * Default clock value item.
 *
 * This item provides the value of the default clock of the data stream
 * of the current packet.
 */
class DefClkValItem final : public Item
{
    friend class ItemSeqIter;

private:
    explicit DefClkValItem() noexcept;

public:
    /*
     * Value of the clock (cycles).
     */
    unsigned long long cycles() const noexcept
    {
        return _mCycles;
    }

    void accept(ItemVisitor& visitor) const override;

private:
    unsigned long long _mCycles = 0;
};

/*
 * Packet information item.
 *
 * This item contains information about the current packet, as found in
 * its context (if any).
 *
 * As per the CTF rules:
 *
 * If expectedTotalLen() and expectedContentLen() are both not set:
 *     The total and content lengths of this packet are the length of
 *     the current data stream (this packet is the only one within its
 *     data stream).
 *
 * If expectedTotalLen() is set, but expectedContentLen() isn't:
 *     The expected content length of this packet is its expected total
 *     length (value of expectedTotalLen()).
 *
 * If expectedContentLen() is set, but expectedTotalLen() isn't:
 *     The expected total length of this packet is its expected content
 *     length (value of expectedContentLen()).
*/
class PktInfoItem final : public Item
{
    friend class ItemSeqIter;

private:
    explicit PktInfoItem() noexcept;

public:
    void accept(ItemVisitor& visitor) const override;

    /*
     * Numeric sequence number of the current packet within its _data
     * stream_ (_not_ within its item sequence).
     */
    const bt2s::optional<unsigned long long>& seqNum() const noexcept
    {
        return _mSeqNum;
    }

    /*
     * Count of total discarded event records at the end of the current
     * packet since the beginning of its _data stream_ (_not_ its item
     * sequence).
     */
    const bt2s::optional<unsigned long long>& discEventRecordCounterSnap() const noexcept
    {
        return _mDiscErCounterSnap;
    }

    /*
     * Expected total length of the current packet.
     *
     * This length _includes_ the packet padding bits before the end of
     * the packet, if any.
    */
    const bt2s::optional<bt2c::DataLen>& expectedTotalLen() const noexcept
    {
        return _mExpectedTotalLen;
    }

    /*
     * Expected content length of the current packet.
     *
     * This length _excludes_ the packet padding bits before the end of
     * the packet, if any: the total length of the packet minus its
     * content length provides its padding length.
     */
    const bt2s::optional<bt2c::DataLen>& expectedContentLen() const noexcept
    {
        return _mExpectedContentLen;
    }

    /*
     * Value (cycles) of the default clock of the data stream of the
     * current packet at its beginning.
     */
    const bt2s::optional<unsigned long long>& beginDefClkVal() const noexcept
    {
        return _mBeginDefClkVal;
    }

    /*
     * Value (cycles) of the default clock of the data stream of the
     * current packet at its end.
     *
     * During the packet decoding process, this default clock value is
     * known _before_ decoding the event records.
     */
    const bt2s::optional<unsigned long long>& endDefClkVal() const noexcept
    {
        return _mEndDefClkVal;
    }

private:
    void _reset() noexcept
    {
        _mSeqNum = bt2s::nullopt;
        _mDiscErCounterSnap = bt2s::nullopt;
        _mExpectedTotalLen = bt2s::nullopt;
        _mExpectedContentLen = bt2s::nullopt;
        _mBeginDefClkVal = bt2s::nullopt;
        _mEndDefClkVal = bt2s::nullopt;
    }

    bt2s::optional<unsigned long long> _mSeqNum;
    bt2s::optional<unsigned long long> _mDiscErCounterSnap;
    bt2s::optional<bt2c::DataLen> _mExpectedTotalLen;
    bt2s::optional<bt2c::DataLen> _mExpectedContentLen;
    bt2s::optional<unsigned long long> _mBeginDefClkVal;
    bt2s::optional<unsigned long long> _mEndDefClkVal;
};

/*
 * Event record information item.
 *
 * This item contains information about the current event record, as
 * found in its header (if any).
 */
class EventRecordInfoItem final : public Item
{
    friend class ItemSeqIter;

private:
    explicit EventRecordInfoItem() noexcept;

public:
    void accept(ItemVisitor& visitor) const override;

    /*
     * Value (cycles) of the default clock of the data stream of the
     * current event record when it occurred.
     */
    const bt2s::optional<unsigned long long>& defClkVal() const noexcept
    {
        return _mDefClkVal;
    }

    /*
     * Class of the current event record, or `nullptr` if the data
     * stream class has no event record classes.
     */
    const EventRecordCls *cls() const noexcept
    {
        return _mCls;
    }

private:
    void _reset() noexcept
    {
        _mCls = nullptr;
        _mDefClkVal = bt2s::nullopt;
    }

    const EventRecordCls *_mCls = nullptr;
    bt2s::optional<unsigned long long> _mDefClkVal;
};

/*
 * Abstract field item base class.
 */
class FieldItem
{
    friend class ItemSeqIter;

protected:
    explicit FieldItem() noexcept = default;

public:
    /*
     * Class of this field.
     */
    const Fc& cls() const noexcept
    {
        return *_mCls;
    }

private:
    const Fc *_mCls;
};

/*
 * Abstract number field item base class.
 */
class NumberFieldItem : public FieldItem
{
    friend class ItemSeqIter;

protected:
    explicit NumberFieldItem() noexcept = default;

private:
    void _val(const unsigned long long val) noexcept
    {
        _mVal.u = val;
    }

    void _val(const long long val) noexcept
    {
        _mVal.i = val;
    }

    void _val(const double val) noexcept
    {
        _mVal.d = val;
    }

protected:
    union
    {
        unsigned long long u;
        long long i;
        double d;
    } _mVal;
};

/*
 * Fixed-length bit array field item.
 */
class FixedLenBitArrayFieldItem : public Item, public NumberFieldItem
{
    friend class ItemSeqIter;

protected:
    explicit FixedLenBitArrayFieldItem(Type type) noexcept;

private:
    explicit FixedLenBitArrayFieldItem() noexcept;

public:
    const FixedLenBitArrayFc& cls() const noexcept
    {
        return FieldItem::cls().asFixedLenBitArray();
    }

    /*
     * Value as an unsigned integer.
     */
    unsigned long long uIntVal() const noexcept
    {
        return _mVal.u;
    }

    /*
     * Returns the value of the bit at the index `index`, where 0 is the
     * index of the least significant bit.
     */
    bool operator[](const unsigned long long index) const noexcept
    {
        BT_ASSERT_DBG(index < *this->cls().len());
        return static_cast<bool>((_mVal.u >> index) & 1);
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Fixed-length boolean field item.
 */
class FixedLenBoolFieldItem final : public FixedLenBitArrayFieldItem
{
    friend class ItemSeqIter;

private:
    explicit FixedLenBoolFieldItem() noexcept;

public:
    const FixedLenBoolFc& cls() const noexcept
    {
        return FieldItem::cls().asFixedLenBool();
    }

    bool val() const noexcept
    {
        return static_cast<bool>(_mVal.u);
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Fixed-length signed integer field item.
 */
class FixedLenSIntFieldItem : public FixedLenBitArrayFieldItem
{
    friend class ItemSeqIter;

protected:
    explicit FixedLenSIntFieldItem(Type type) noexcept;

private:
    explicit FixedLenSIntFieldItem() noexcept;

public:
    const FixedLenSIntFc& cls() const noexcept
    {
        return FieldItem::cls().asFixedLenSInt();
    }

    long long val() const noexcept
    {
        return _mVal.i;
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Fixed-length unsigned integer field item.
 */
class FixedLenUIntFieldItem : public FixedLenBitArrayFieldItem
{
    friend class ItemSeqIter;

protected:
    explicit FixedLenUIntFieldItem(Type type) noexcept;

private:
    explicit FixedLenUIntFieldItem() noexcept;

public:
    const FixedLenUIntFc& cls() const noexcept
    {
        return FieldItem::cls().asFixedLenUInt();
    }

    unsigned long long val() const noexcept
    {
        return _mVal.u;
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Fixed-length signed enumeration field item.
 */
class FixedLenSEnumFieldItem final : public FixedLenSIntFieldItem
{
    friend class ItemSeqIter;

private:
    explicit FixedLenSEnumFieldItem() noexcept;

public:
    const FixedLenSEnumFc& cls() const noexcept
    {
        return FieldItem::cls().asFixedLenSEnum();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Fixed-length unsigned enumeration field item.
 */
class FixedLenUEnumFieldItem final : public FixedLenUIntFieldItem
{
    friend class ItemSeqIter;

private:
    explicit FixedLenUEnumFieldItem() noexcept;

public:
    const FixedLenUEnumFc& cls() const noexcept
    {
        return FieldItem::cls().asFixedLenUEnum();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Fixed-length floating point number field item.
 */
class FixedLenFloatFieldItem final : public FixedLenBitArrayFieldItem
{
    friend class ItemSeqIter;

private:
    explicit FixedLenFloatFieldItem() noexcept;

public:
    const FixedLenFloatFc& cls() const noexcept
    {
        return FieldItem::cls().asFixedLenFloat();
    }

    double val() const noexcept
    {
        return _mVal.d;
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Variable-length integer field item.
 */
class VarLenIntFieldItem : public Item, public NumberFieldItem
{
    friend class ItemSeqIter;

protected:
    explicit VarLenIntFieldItem(Type type) noexcept;

public:
    const VarLenIntFc& cls() const noexcept
    {
        return FieldItem::cls().asVarLenInt();
    }

    /*
     * Integer length.
     *
     * This is the length of the decoded integer, not the length of the
     * field (use fieldLen()).
     */
    bt2c::DataLen len() const noexcept
    {
        return _mLen;
    }

    /*
     * Field length.
     *
     * This is the length of the field itself, not the length of the
     * decoded integer (use len()).
     */
    bt2c::DataLen fieldLen() const noexcept
    {
        /* `*_mLen` doesn't need to be a multiple of 7 */
        return bt2c::DataLen::fromBytes((*_mLen + 6) / 7);
    }

private:
    bt2c::DataLen _mLen;
};

/*
 * Variable-length signed integer field item.
 */
class VarLenSIntFieldItem : public VarLenIntFieldItem
{
    friend class ItemSeqIter;

protected:
    explicit VarLenSIntFieldItem(Type type) noexcept;

private:
    explicit VarLenSIntFieldItem() noexcept;

public:
    const VarLenSIntFc& cls() const noexcept
    {
        return FieldItem::cls().asVarLenSInt();
    }

    long long val() const noexcept
    {
        return _mVal.i;
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Variable-length unsigned integer field item.
 */
class VarLenUIntFieldItem : public VarLenIntFieldItem
{
    friend class ItemSeqIter;

protected:
    explicit VarLenUIntFieldItem(Type type) noexcept;

private:
    explicit VarLenUIntFieldItem() noexcept;

public:
    const VarLenUIntFc& cls() const noexcept
    {
        return FieldItem::cls().asVarLenUInt();
    }

    unsigned long long val() const noexcept
    {
        return _mVal.u;
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Variable-length signed enumeration field item.
 */
class VarLenSEnumFieldItem final : public VarLenSIntFieldItem
{
    friend class ItemSeqIter;

private:
    explicit VarLenSEnumFieldItem() noexcept;

public:
    const VarLenSEnumFc& cls() const noexcept
    {
        return FieldItem::cls().asVarLenSEnum();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Variable-length unsigned enumeration field item.
 */
class VarLenUEnumFieldItem final : public VarLenUIntFieldItem
{
    friend class ItemSeqIter;

private:
    explicit VarLenUEnumFieldItem() noexcept;

public:
    const VarLenUEnumFc& cls() const noexcept
    {
        return FieldItem::cls().asVarLenUEnum();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Null-terminated string field beginning item.
 *
 * This item indicates the beginning of a null-terminated string field.
 *
 * The next `StrFieldSubstrItem` items before the next
 * `NullTerminatedStrFieldEndItem are consecutive substrings of this
 * beginning null-terminated string field.
 */
class NullTerminatedStrFieldBeginItem final : public BeginItem, public FieldItem
{
    friend class ItemSeqIter;

private:
    explicit NullTerminatedStrFieldBeginItem() noexcept;

public:
    const NullTerminatedStrFc& cls() const noexcept
    {
        return FieldItem::cls().asNullTerminatedStr();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Null-terminated string field end item.
 *
 * This item indicates the end of a null-terminated string field.
 */
class NullTerminatedStrFieldEndItem final : public EndItem, public FieldItem
{
    friend class ItemSeqIter;

private:
    explicit NullTerminatedStrFieldEndItem() noexcept;

public:
    const NullTerminatedStrFc& cls() const noexcept
    {
        return FieldItem::cls().asNullTerminatedStr();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * String field substring item.
 *
 * This item may occur:
 *
 * Null-terminated string field:
 *     Between `NullTerminatedStrFieldBeginItem` and
 *     `NullTerminatedStrFieldEndItem  items.
 *
 * Static-length string field:
 *     Between `StaticLenStrFieldBeginItem` and
 *     `StaticLenStrFieldEndItem` items.
 *
 * Dynamic-length string field:
 *     Between `DynLenStrFieldBeginItem` and `DynLenStrFieldEndItem`
 *     items.
 *
 * begin() points to the first byte of the substring and end() points to
 * the byte _after_ the last byte of the substring. Use size() to
 * compute the size of the substring _data_ in bytes.
 *
 * The whole substring may contain _zero or more_ null bytes. If there's
 * a null byte between begin() and end(), the substring finishes at this
 * point, but for static-length and dynamic-length strings, there may be
 * other non-null bytes before end() which are still part of the data
 * stream. Knowing this:
 *
 * • Use strEnd() to get the end of the possibly null-terminated
 *   substring (the first null byte or end() if none).
 *
 * • Use strSize() to get the size of the possibly null-terminated
 *   substring.
 *
 * • Use str() to get a string containing the text data of the
 *   substring (before any null byte).
 *
 * • Use strView() to get a string view containing the text data of the
 *   substring (before any null byte).
 */
class StrFieldSubstrItem final : public Item
{
    friend class ItemSeqIter;

private:
    explicit StrFieldSubstrItem() noexcept;

public:
    /*
     * Beginning of the data of this substring (_not_ necessarily
     * null-terminated).
     */
    const char *begin() const noexcept
    {
        return _mBegin;
    }

    /*
     * End of the data of this substring (points to the byte _after_ the
     * last byte of the substring).
     *
     * Use strEnd() to get the end of the possibly null-terminated
     * substring.
     */
    const char *end() const noexcept
    {
        return _mEnd;
    }

    /*
     * End of this possibly null-terminated substring (points to either
     * the first null byte, or is end() if none).
     */
    const char *strEnd() const noexcept
    {
        return std::find(_mBegin, _mEnd, '\0');
    }

    /*
     * Size of this substring, including null bytes and characters after
     * that, if any.
     *
     * Use strSize() to get the size of this possibly null-terminated
     * string, excluding any terminating null byte.
     */
    bt2c::DataLen size() const noexcept
    {
        return bt2c::DataLen::fromBytes(_mEnd - _mBegin);
    }

    /*
     * Size of this possibly null-terminated substring, excluding any
     * terminating null byte.
     */
    bt2c::DataLen strSize() const noexcept
    {
        return bt2c::DataLen::fromBytes(this->strEnd() - _mBegin);
    }

    /*
     * String containing the text data (between begin() and strEnd()) of
     * this substring.
     */
    std::string str() const
    {
        return {_mBegin, this->strEnd()};
    }

    /*
     * String view wrapping the text data (between begin() and strEnd())
     * of this substring.
     */
    bt2s::string_view strView() const
    {
        return {_mBegin, static_cast<bt2s::string_view::size_type>(this->strSize().bytes())};
    }

    void accept(ItemVisitor& visitor) const override;

private:
    const char *_mBegin = nullptr;
    const char *_mEnd = nullptr;
};

/*
 * BLOB field section item.
 *
 * This item may occur:
 *
 * Data stream static-length BLOB field:
 *     Between `StaticLenBlobFieldBeginItem` and
 *     `StaticLenBlobFieldEndItem` items.
 *
 * Data stream dynamic-length BLOB field:
 *     Between `DynLenBlobFieldBeginItem` and `DynLenBlobFieldEndItem`
 *     items.
 *
 * begin() points to the first byte of the BLOB field section and end()
 * points to the byte _after_ the last byte of the BLOB field section.
 * Use size() to compute the size of the BLOB field section.
 */
class BlobFieldSectionItem final : public Item
{
    friend class ItemSeqIter;

private:
    explicit BlobFieldSectionItem() noexcept;

public:
    /*
     * Beginning of the data of this BLOB field section.
     */
    const std::uint8_t *begin() const noexcept
    {
        return _mBegin;
    }

    /*
     * End of the data of this BLOB field section.
     */
    const std::uint8_t *end() const noexcept
    {
        return _mEnd;
    }

    /*
     * Size of this BLOB field section.
     */
    bt2c::DataLen size() const noexcept
    {
        return bt2c::DataLen::fromBytes(_mEnd - _mBegin);
    }

    void accept(ItemVisitor& visitor) const override;

private:
    const std::uint8_t *_mBegin = nullptr;
    const std::uint8_t *_mEnd = nullptr;
};

/*
 * Abstract array field beginning item base class.
 */
class ArrayFieldBeginItem : public BeginItem, public FieldItem
{
    friend class ItemSeqIter;

protected:
    explicit ArrayFieldBeginItem(Type type) noexcept;

public:
    const ArrayFc& cls() const noexcept
    {
        return FieldItem::cls().asArray();
    }
};

/*
 * Abstract array field end item base class.
 */
class ArrayFieldEndItem : public EndItem, public FieldItem
{
    friend class ItemSeqIter;

protected:
    explicit ArrayFieldEndItem(Type type) noexcept;

public:
    const ArrayFc& cls() const noexcept
    {
        return FieldItem::cls().asArray();
    }
};

/*
 * Static-length array field beginning item.
 *
 * This item indicates the beginning of a static-length array field.
 *
 * The next items until the next `StaticLenArrayFieldEndItem` at the
 * same level are all part of this static-length array field.
 */
class StaticLenArrayFieldBeginItem final : public ArrayFieldBeginItem
{
    friend class ItemSeqIter;

private:
    explicit StaticLenArrayFieldBeginItem() noexcept;

public:
    const StaticLenArrayFc& cls() const noexcept
    {
        return FieldItem::cls().asStaticLenArray();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Static-length array field end item.
 *
 * This item indicates the end of a static-length array field.
 */
class StaticLenArrayFieldEndItem final : public ArrayFieldEndItem
{
    friend class ItemSeqIter;

private:
    explicit StaticLenArrayFieldEndItem() noexcept;

public:
    const StaticLenArrayFc& cls() const noexcept
    {
        return FieldItem::cls().asStaticLenArray();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Dynamic-length array field beginning item.
 *
 * This item indicates the beginning of a dynamic-length array field.
 *
 * The next items until the next `DynLenArrayFieldEndItem` at the same
 * level are all part of this dynamic-length array field.
 */
class DynLenArrayFieldBeginItem final : public ArrayFieldBeginItem
{
    friend class ItemSeqIter;

private:
    explicit DynLenArrayFieldBeginItem() noexcept;

public:
    const DynLenArrayFc& cls() const noexcept
    {
        return FieldItem::cls().asDynLenArray();
    }

    /*
     * Array length (number of elements).
     */
    std::size_t len() const noexcept
    {
        return _mLen;
    }

    void accept(ItemVisitor& visitor) const override;

private:
    std::size_t _mLen = 0;
};

/*
 * Dynamic-length array field end item.
 *
 * This item indicates the end of a dynamic-length array field.
 */
class DynLenArrayFieldEndItem final : public ArrayFieldEndItem
{
    friend class ItemSeqIter;

private:
    explicit DynLenArrayFieldEndItem() noexcept;

public:
    const DynLenArrayFc& cls() const noexcept
    {
        return FieldItem::cls().asDynLenArray();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Abstract non-null-terminated string field beginning item base class.
 */
class NonNullTerminatedStrFieldBeginItem : public BeginItem, public FieldItem
{
    friend class ItemSeqIter;

protected:
    using BeginItem::BeginItem;

public:
    const NonNullTerminatedStrFc& cls() const noexcept
    {
        return FieldItem::cls().asNonNullTerminatedStr();
    }
};

/*
 * Abstract non-null-terminated string field end item base class.
 */
class NonNullTerminatedStrFieldEndItem : public EndItem, public FieldItem
{
    friend class ItemSeqIter;

protected:
    using EndItem::EndItem;

public:
    const NonNullTerminatedStrFc& cls() const noexcept
    {
        return FieldItem::cls().asNonNullTerminatedStr();
    }
};

/*
 * Static-length string field beginning item.
 *
 * This item indicates the beginning of a static-length string field.
 *
 * The next `StrFieldSubstrItem` items before the next
 * `StaticLenStrFieldEndItem` are consecutive substrings of this
 * beginning static-length string field.
 */
class StaticLenStrFieldBeginItem final : public NonNullTerminatedStrFieldBeginItem
{
    friend class ItemSeqIter;

private:
    explicit StaticLenStrFieldBeginItem() noexcept;

public:
    const StaticLenStrFc& cls() const noexcept
    {
        return FieldItem::cls().asStaticLenStr();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Static-length string field end item.
 *
 * This item indicates the end of a static-length string field.
 */
class StaticLenStrFieldEndItem final : public NonNullTerminatedStrFieldEndItem
{
    friend class ItemSeqIter;

private:
    explicit StaticLenStrFieldEndItem() noexcept;

public:
    const StaticLenStrFc& cls() const noexcept
    {
        return FieldItem::cls().asStaticLenStr();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Dynamic-length string field beginning item.
 *
 * This item indicates the beginning of a dynamic-length string field.
 *
 * The next `StrFieldSubstrItem` items before the next
 * `DynLenStrFieldEndItem` are consecutive substrings of this beginning
 * dynamic-length string field.
 */
class DynLenStrFieldBeginItem final : public NonNullTerminatedStrFieldBeginItem
{
    friend class ItemSeqIter;

private:
    explicit DynLenStrFieldBeginItem() noexcept;

public:
    const DynLenStrFc& cls() const noexcept
    {
        return FieldItem::cls().asDynLenStr();
    }

    /*
     * Field length.
     */
    bt2c::DataLen len() const noexcept
    {
        return _mLen;
    }

    void accept(ItemVisitor& visitor) const override;

protected:
    bt2c::DataLen _mLen = bt2c::DataLen::fromBytes(0);
};

/*
 * Dynamic-length string field end item.
 *
 * This item indicates the end of a dynamic-length string field.
 */
class DynLenStrFieldEndItem final : public NonNullTerminatedStrFieldEndItem
{
    friend class ItemSeqIter;

private:
    explicit DynLenStrFieldEndItem() noexcept;

public:
    const DynLenStrFc& cls() const noexcept
    {
        return FieldItem::cls().asDynLenStr();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Abstract BLOB field beginning item base class.
 */
class BlobFieldBeginItem : public BeginItem, public FieldItem
{
    friend class ItemSeqIter;

protected:
    using BeginItem::BeginItem;

public:
    const BlobFc& cls() const noexcept
    {
        return FieldItem::cls().asBlob();
    }
};

/*
 * Abstract BLOB field end item base class.
 */
class BlobFieldEndItem : public EndItem, public FieldItem
{
    friend class ItemSeqIter;

protected:
    using EndItem::EndItem;

public:
    const BlobFc& cls() const noexcept
    {
        return FieldItem::cls().asBlob();
    }
};

/*
 * Static-length BLOB field beginning item.
 *
 * This item indicates the beginning of a static-length BLOB field.
 *
 * The next `BlobFieldSectionItem` items before the next
 * `StaticLenBlobFieldEndItem` are consecutive BLOB field sections of
 * this beginning static-length BLOB field.
 */
class StaticLenBlobFieldBeginItem final : public BlobFieldBeginItem
{
    friend class ItemSeqIter;

private:
    explicit StaticLenBlobFieldBeginItem() noexcept;

public:
    const StaticLenBlobFc& cls() const noexcept
    {
        return FieldItem::cls().asStaticLenBlob();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Static-length BLOB field end item.
 *
 * This item indicates the end of a static-length BLOB field.
 */
class StaticLenBlobFieldEndItem final : public BlobFieldEndItem
{
    friend class ItemSeqIter;

private:
    explicit StaticLenBlobFieldEndItem() noexcept;

public:
    const StaticLenBlobFc& cls() const noexcept
    {
        return FieldItem::cls().asStaticLenBlob();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Dynamic-length BLOB field beginning item.
 *
 * This item indicates the beginning of a dynamic-length BLOB field.
 *
 * The next `BlobFieldSectionItem` items before the next
 * `DynLenBlobFieldEndItem` are consecutive BLOB field sections of this
 * beginning dynamic-length BLOB field.
 */
class DynLenBlobFieldBeginItem final : public BlobFieldBeginItem
{
    friend class ItemSeqIter;

private:
    explicit DynLenBlobFieldBeginItem() noexcept;

public:
    const DynLenBlobFc& cls() const noexcept
    {
        return FieldItem::cls().asDynLenBlob();
    }

    /*
     * Field length.
     */
    bt2c::DataLen len() const noexcept
    {
        return _mLen;
    }

    void accept(ItemVisitor& visitor) const override;

protected:
    bt2c::DataLen _mLen = bt2c::DataLen::fromBytes(0);
};

/*
 * Dynamic-length BLOB field end item.
 *
 * This item indicates the end of a dynamic-length BLOB field.
 */
class DynLenBlobFieldEndItem final : public BlobFieldEndItem
{
    friend class ItemSeqIter;

private:
    explicit DynLenBlobFieldEndItem() noexcept;

public:
    const DynLenBlobFc& cls() const noexcept
    {
        return FieldItem::cls().asDynLenBlob();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Structure field beginning item.
 *
 * This item indicates the beginning of a structure field.
 *
 * The next items until the next `StructFieldEndItem` at the same level
 * are all part of this structure field.
 */
class StructFieldBeginItem final : public BeginItem, public FieldItem
{
    friend class ItemSeqIter;

private:
    explicit StructFieldBeginItem() noexcept;

public:
    const StructFc& cls() const noexcept
    {
        return FieldItem::cls().asStruct();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Structure field end item.
 *
 * This item indicates the end of a structure field.
 */
class StructFieldEndItem final : public EndItem, public FieldItem
{
    friend class ItemSeqIter;

private:
    explicit StructFieldEndItem() noexcept;

public:
    const StructFc& cls() const noexcept
    {
        return FieldItem::cls().asStruct();
    }

    void accept(ItemVisitor& visitor) const override;
};

/*
 * Abstract variant field beginning item base class.
 */
class VariantFieldBeginItem : public BeginItem, public FieldItem
{
    friend class ItemSeqIter;

protected:
    explicit VariantFieldBeginItem(Type type) noexcept;

public:
    unsigned long long selectedOptIndex() const noexcept
    {
        return _mSelectedOptIndex;
    }

private:
    unsigned long long _mSelectedOptIndex = 0;
};

/*
 * Abstract variant field end item base class.
 */
class VariantFieldEndItem : public EndItem, public FieldItem
{
    friend class ItemSeqIter;

protected:
    explicit VariantFieldEndItem(Type type) noexcept;
};

/*
 * Abstract variant field with integer selector beginning item base
 * class.
 */
template <typename VariantFcT, typename SelValT, Item::Type TypeV>
class VariantFieldWithIntSelBeginItem : public VariantFieldBeginItem
{
    friend class ItemSeqIter;

protected:
    explicit VariantFieldWithIntSelBeginItem() noexcept : VariantFieldBeginItem {TypeV}
    {
    }

public:
    const VariantFcT& cls() const noexcept
    {
        return static_cast<const VariantFcT&>(this->cls());
    }

    /*
     * Value of the variant field selector.
     */
    SelValT selVal() const noexcept
    {
        return _mSelVal;
    }

    /*
     * Selected option of the variant field class.
     */
    const typename VariantFcT::Opt& clsOpt() const noexcept
    {
        return *_mOpt;
    }

private:
    SelValT _mSelVal = 0;
    const typename VariantFcT::Opt *_mOpt = nullptr;
};

/*
 * Abstract variant field with integer selector end item base class.
 */
template <typename VariantFcT, Item::Type TypeV>
class VariantFieldWithIntSelEndItem : public VariantFieldEndItem
{
    friend class ItemSeqIter;

protected:
    explicit VariantFieldWithIntSelEndItem() noexcept : VariantFieldEndItem {TypeV}
    {
    }

public:
    const VariantFcT& cls() const noexcept
    {
        return static_cast<const VariantFcT&>(this->cls());
    }
};

/*
 * Variant field with unsigned integer selector beginning item.
 *
 * This item indicates the beginning of a variant field having an
 * unsigned integer selector.
 *
 * The next item is the selected field item of this variant field.
 * Expect a `VariantFieldWithUIntSelEndItem` after this next item at the
 * same level.
 */
class VariantFieldWithUIntSelBeginItem final :
    public VariantFieldWithIntSelBeginItem<VariantWithUIntSelFc, unsigned long long,
                                           Item::Type::VARIANT_FIELD_WITH_UINT_SEL_BEGIN>
{
    friend class ItemSeqIter;

private:
    explicit VariantFieldWithUIntSelBeginItem() = default;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Variant field with unsigned integer selector end item.
 *
 * This item indicates the end of a variant field having an unsigned
 * integer selector.
 */
class VariantFieldWithUIntSelEndItem final :
    public VariantFieldWithIntSelEndItem<VariantWithUIntSelFc,
                                         Item::Type::VARIANT_FIELD_WITH_UINT_SEL_END>
{
    friend class ItemSeqIter;

private:
    explicit VariantFieldWithUIntSelEndItem() = default;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Variant field with signed integer selector beginning item.
 *
 * This item indicates the beginning of a variant field having a
 * signed integer selector.
 *
 * The next item is the selected field item of this variant field.
 * Expect a `VariantFieldWithSIntSelEndItem` after this next item at the
 * same level.
 */
class VariantFieldWithSIntSelBeginItem final :
    public VariantFieldWithIntSelBeginItem<VariantWithSIntSelFc, long long,
                                           Item::Type::VARIANT_FIELD_WITH_SINT_SEL_BEGIN>
{
    friend class ItemSeqIter;

private:
    explicit VariantFieldWithSIntSelBeginItem() = default;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Variant field with signed integer selector end item.
 *
 * This item indicates the end of a variant field having a signed
 * integer selector.
 */
class VariantFieldWithSIntSelEndItem final :
    public VariantFieldWithIntSelEndItem<VariantWithSIntSelFc,
                                         Item::Type::VARIANT_FIELD_WITH_SINT_SEL_END>
{
    friend class ItemSeqIter;

private:
    explicit VariantFieldWithSIntSelEndItem() = default;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Abstract optional field beginning item base class.
 */
class OptionalFieldBeginItem : public BeginItem, public FieldItem
{
    friend class ItemSeqIter;

protected:
    explicit OptionalFieldBeginItem(Type type) noexcept;

public:
    const OptionalFc& cls() const noexcept
    {
        return FieldItem::cls().asOptional();
    }

    /*
     * Whether or not this optional field is enabled (contains data).
     */
    bool isEnabled() const noexcept
    {
        return _mIsEnabled;
    }

private:
    bool _mIsEnabled = false;
};

/*
 * Abstract optional field end item base class.
 */
class OptionalFieldEndItem : public EndItem, public FieldItem
{
    friend class ItemSeqIter;

protected:
    explicit OptionalFieldEndItem(Type type) noexcept;

public:
    const OptionalFc& cls() const noexcept
    {
        return FieldItem::cls().asOptional();
    }
};

/*
 * Optional field with boolean selector beginning item.
 *
 * This item indicates the beginning of an optional field having a
 * boolean selector.
 *
 * The next item, if isEnabled() returns `true`, is the contained field
 * item of this optional field. Expect an
 * `OptionalFieldWithBoolSelEndItem` after this at the same level.
 */
class OptionalFieldWithBoolSelBeginItem final : public OptionalFieldBeginItem
{
    friend class ItemSeqIter;

private:
    explicit OptionalFieldWithBoolSelBeginItem() noexcept;

public:
    const OptionalWithBoolSelFc& cls() const noexcept
    {
        return FieldItem::cls().asOptionalWithBoolSel();
    }

    /*
     * Value of the optional field selector.
     */
    bool selVal() const noexcept
    {
        return _mSelVal;
    }

    void accept(ItemVisitor& visitor) const override;

private:
    bool _mSelVal = false;
};

/*
 * Optional field with boolean selector end item.
 *
 * This item indicates the end of an optional field having a boolean
 * selector.
 */
class OptionalFieldWithBoolSelEndItem final : public OptionalFieldEndItem
{
    friend class ItemSeqIter;

private:
    explicit OptionalFieldWithBoolSelEndItem() noexcept;

public:
    const OptionalWithBoolSelFc& cls() const noexcept
    {
        return FieldItem::cls().asOptionalWithBoolSel();
    }

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Abstract optional field with integer selector beginning item base
 * class.
 */
template <typename OptionalFcT, typename SelValT, Item::Type TypeV>
class OptionalFieldWithIntSelBeginItem : public OptionalFieldBeginItem
{
    friend class ItemSeqIter;

protected:
    explicit OptionalFieldWithIntSelBeginItem() noexcept : OptionalFieldBeginItem {TypeV}
    {
    }

public:
    const OptionalFcT& cls() const noexcept
    {
        return static_cast<const OptionalFcT&>(this->cls());
    }

    /*
     * Value of the optional field selector.
     */
    SelValT selVal() const noexcept
    {
        return _mSelVal;
    }

private:
    SelValT _mSelVal = 0;
};

/*
 * Abstract optional field with integer selector end item base class.
 */
template <typename OptionalFcT, Item::Type TypeV>
class OptionalFieldWithIntSelEndItem : public OptionalFieldEndItem
{
    friend class ItemSeqIter;

protected:
    explicit OptionalFieldWithIntSelEndItem() noexcept : OptionalFieldEndItem {TypeV}
    {
    }

public:
    const OptionalFcT& cls() const noexcept
    {
        return static_cast<const OptionalFcT&>(this->cls());
    }
};

/*
 * Optional field with unsigned integer selector beginning item.
 *
 * This item indicates the beginning of an optional field having an
 * unsigned integer selector.
 *
 * The next item, if isEnabled() returns `true`, is the contained field
 * item of this optional field. Expect an
 * `OptionalFieldWithUIntSelEndItem` after this at the same level.
 */
class OptionalFieldWithUIntSelBeginItem final :
    public OptionalFieldWithIntSelBeginItem<OptionalWithUIntSelFc, unsigned long long,
                                            Item::Type::OPTIONAL_FIELD_WITH_UINT_SEL_BEGIN>
{
    friend class ItemSeqIter;

private:
    explicit OptionalFieldWithUIntSelBeginItem() = default;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Optional field with unsigned integer selector end item.
 *
 * This item indicates the end of an optional field with an
 * unsigned integer selector.
 */
class OptionalFieldWithUIntSelEndItem final :
    public OptionalFieldWithIntSelEndItem<OptionalWithUIntSelFc,
                                          Item::Type::OPTIONAL_FIELD_WITH_UINT_SEL_END>
{
    friend class ItemSeqIter;

private:
    explicit OptionalFieldWithUIntSelEndItem() = default;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Optional field with signed integer selector beginning item.
 *
 * This item indicates the beginning of an optional field having a
 * signed integer selector.
 *
 * The next item, if isEnabled() returns `true`, is the contained field
 * item of this optional field. Expect an
 * `OptionalFieldWithSIntSelEndItem` after this at the same level.
 */
class OptionalFieldWithSIntSelBeginItem final :
    public OptionalFieldWithIntSelBeginItem<OptionalWithSIntSelFc, long long,
                                            Item::Type::OPTIONAL_FIELD_WITH_SINT_SEL_BEGIN>
{
    friend class ItemSeqIter;

private:
    explicit OptionalFieldWithSIntSelBeginItem() = default;

public:
    void accept(ItemVisitor& visitor) const override;
};

/*
 * Optional field with signed integer selector end item.
 *
 * This item indicates the end of an optional field with a signed
 * integer selector.
 */
class OptionalFieldWithSIntSelEndItem final :
    public OptionalFieldWithIntSelEndItem<OptionalWithSIntSelFc,
                                          Item::Type::OPTIONAL_FIELD_WITH_SINT_SEL_END>
{
    friend class ItemSeqIter;

private:
    explicit OptionalFieldWithSIntSelEndItem() = default;

public:
    void accept(ItemVisitor& visitor) const override;
};

static inline const char *format_as(const Item::Type type)
{
    switch (type) {
    case Item::Type::PKT_BEGIN:
        return "PKT_BEGIN";
    case Item::Type::PKT_END:
        return "PKT_END";
    case Item::Type::SCOPE_BEGIN:
        return "SCOPE_BEGIN";
    case Item::Type::SCOPE_END:
        return "SCOPE_END";
    case Item::Type::PKT_CONTENT_BEGIN:
        return "PKT_CONTENT_BEGIN";
    case Item::Type::PKT_CONTENT_END:
        return "PKT_CONTENT_END";
    case Item::Type::EVENT_RECORD_BEGIN:
        return "EVENT_RECORD_BEGIN";
    case Item::Type::EVENT_RECORD_END:
        return "EVENT_RECORD_END";
    case Item::Type::PKT_MAGIC_NUMBER:
        return "PKT_MAGIC_NUMBER";
    case Item::Type::METADATA_STREAM_UUID:
        return "METADATA_STREAM_UUID";
    case Item::Type::DATA_STREAM_INFO:
        return "DATA_STREAM_INFO";
    case Item::Type::DEF_CLK_VALUE:
        return "DEF_CLK_VALUE";
    case Item::Type::PKT_INFO:
        return "PKT_INFO";
    case Item::Type::EVENT_RECORD_INFO:
        return "EVENT_RECORD_INFO";
    case Item::Type::FIXED_LEN_BIT_ARRAY_FIELD:
        return "FIXED_LEN_BIT_ARRAY_FIELD";
    case Item::Type::FIXED_LEN_BOOL_FIELD:
        return "FIXED_LEN_BOOL_FIELD";
    case Item::Type::FIXED_LEN_SINT_FIELD:
        return "FIXED_LEN_SINT_FIELD";
    case Item::Type::FIXED_LEN_UINT_FIELD:
        return "FIXED_LEN_UINT_FIELD";
    case Item::Type::FIXED_LEN_FLOAT_FIELD:
        return "FIXED_LEN_FLOAT_FIELD";
    case Item::Type::FIXED_LEN_SENUM_FIELD:
        return "FIXED_LEN_SENUM_FIELD";
    case Item::Type::FIXED_LEN_UENUM_FIELD:
        return "FIXED_LEN_UENUM_FIELD";
    case Item::Type::VAR_LEN_SINT_FIELD:
        return "VAR_LEN_SINT_FIELD";
    case Item::Type::VAR_LEN_UINT_FIELD:
        return "VAR_LEN_UINT_FIELD";
    case Item::Type::VAR_LEN_SENUM_FIELD:
        return "VAR_LEN_SENUM_FIELD";
    case Item::Type::VAR_LEN_UENUM_FIELD:
        return "VAR_LEN_UENUM_FIELD";
    case Item::Type::NULL_TERMINATED_STR_FIELD_BEGIN:
        return "NULL_TERMINATED_STR_FIELD_BEGIN";
    case Item::Type::NULL_TERMINATED_STR_FIELD_END:
        return "NULL_TERMINATED_STR_FIELD_END";
    case Item::Type::STR_FIELD_SUBSTR:
        return "STR_FIELD_SUBSTR";
    case Item::Type::BLOB_FIELD_SECTION:
        return "BLOB_FIELD_SECTION";
    case Item::Type::STRUCT_FIELD_BEGIN:
        return "STRUCT_FIELD_BEGIN";
    case Item::Type::STRUCT_FIELD_END:
        return "STRUCT_FIELD_END";
    case Item::Type::STATIC_LEN_ARRAY_FIELD_BEGIN:
        return "STATIC_LEN_ARRAY_FIELD_BEGIN";
    case Item::Type::STATIC_LEN_ARRAY_FIELD_END:
        return "STATIC_LEN_ARRAY_FIELD_END";
    case Item::Type::DYN_LEN_ARRAY_FIELD_BEGIN:
        return "DYN_LEN_ARRAY_FIELD_BEGIN";
    case Item::Type::DYN_LEN_ARRAY_FIELD_END:
        return "DYN_LEN_ARRAY_FIELD_END";
    case Item::Type::STATIC_LEN_BLOB_FIELD_BEGIN:
        return "STATIC_LEN_BLOB_FIELD_BEGIN";
    case Item::Type::STATIC_LEN_BLOB_FIELD_END:
        return "STATIC_LEN_BLOB_FIELD_END";
    case Item::Type::DYN_LEN_BLOB_FIELD_BEGIN:
        return "DYN_LEN_BLOB_FIELD_BEGIN";
    case Item::Type::DYN_LEN_BLOB_FIELD_END:
        return "DYN_LEN_BLOB_FIELD_END";
    case Item::Type::STATIC_LEN_STR_FIELD_BEGIN:
        return "STATIC_LEN_STR_FIELD_BEGIN";
    case Item::Type::STATIC_LEN_STR_FIELD_END:
        return "STATIC_LEN_STR_FIELD_END";
    case Item::Type::DYN_LEN_STR_FIELD_BEGIN:
        return "DYN_LEN_STR_FIELD_BEGIN";
    case Item::Type::DYN_LEN_STR_FIELD_END:
        return "DYN_LEN_STR_FIELD_END";
    case Item::Type::VARIANT_FIELD_WITH_SINT_SEL_BEGIN:
        return "VARIANT_FIELD_WITH_SINT_SEL_BEGIN";
    case Item::Type::VARIANT_FIELD_WITH_SINT_SEL_END:
        return "VARIANT_FIELD_WITH_SINT_SEL_END";
    case Item::Type::VARIANT_FIELD_WITH_UINT_SEL_BEGIN:
        return "VARIANT_FIELD_WITH_UINT_SEL_BEGIN";
    case Item::Type::VARIANT_FIELD_WITH_UINT_SEL_END:
        return "VARIANT_FIELD_WITH_UINT_SEL_END";
    case Item::Type::OPTIONAL_FIELD_WITH_BOOL_SEL_BEGIN:
        return "OPTIONAL_FIELD_WITH_BOOL_SEL_BEGIN";
    case Item::Type::OPTIONAL_FIELD_WITH_BOOL_SEL_END:
        return "OPTIONAL_FIELD_WITH_BOOL_SEL_END";
    case Item::Type::OPTIONAL_FIELD_WITH_SINT_SEL_BEGIN:
        return "OPTIONAL_FIELD_WITH_SINT_SEL_BEGIN";
    case Item::Type::OPTIONAL_FIELD_WITH_SINT_SEL_END:
        return "OPTIONAL_FIELD_WITH_SINT_SEL_END";
    case Item::Type::OPTIONAL_FIELD_WITH_UINT_SEL_BEGIN:
        return "OPTIONAL_FIELD_WITH_UINT_SEL_BEGIN";
    case Item::Type::OPTIONAL_FIELD_WITH_UINT_SEL_END:
        return "OPTIONAL_FIELD_WITH_UINT_SEL_END";
    }

    bt_common_abort();
}

inline const BlobFieldSectionItem& Item::asBlobFieldSectionItem() const noexcept
{
    return static_cast<const BlobFieldSectionItem&>(*this);
}

inline const DataStreamInfoItem& Item::asDataStreamInfoItem() const noexcept
{
    return static_cast<const DataStreamInfoItem&>(*this);
}

inline const DefClkValItem& Item::asDefClkValItem() const noexcept
{
    return static_cast<const DefClkValItem&>(*this);
}

inline const DynLenArrayFieldBeginItem& Item::asDynLenArrayFieldBeginItem() const noexcept
{
    return static_cast<const DynLenArrayFieldBeginItem&>(*this);
}

inline const DynLenArrayFieldEndItem& Item::asDynLenArrayFieldEndItem() const noexcept
{
    return static_cast<const DynLenArrayFieldEndItem&>(*this);
}

inline const DynLenBlobFieldBeginItem& Item::asDynLenBlobFieldBeginItem() const noexcept
{
    return static_cast<const DynLenBlobFieldBeginItem&>(*this);
}

inline const DynLenBlobFieldEndItem& Item::asDynLenBlobFieldEndItem() const noexcept
{
    return static_cast<const DynLenBlobFieldEndItem&>(*this);
}

inline const DynLenStrFieldBeginItem& Item::asDynLenStrFieldBeginItem() const noexcept
{
    return static_cast<const DynLenStrFieldBeginItem&>(*this);
}

inline const DynLenStrFieldEndItem& Item::asDynLenStrFieldEndItem() const noexcept
{
    return static_cast<const DynLenStrFieldEndItem&>(*this);
}

inline const EventRecordBeginItem& Item::asEventRecordBeginItem() const noexcept
{
    return static_cast<const EventRecordBeginItem&>(*this);
}

inline const EventRecordEndItem& Item::asEventRecordEndItem() const noexcept
{
    return static_cast<const EventRecordEndItem&>(*this);
}

inline const EventRecordInfoItem& Item::asEventRecordInfoItem() const noexcept
{
    return static_cast<const EventRecordInfoItem&>(*this);
}

inline const FixedLenBitArrayFieldItem& Item::asFixedLenBitArrayFieldItem() const noexcept
{
    return static_cast<const FixedLenBitArrayFieldItem&>(*this);
}

inline const FixedLenBoolFieldItem& Item::asFixedLenBoolFieldItem() const noexcept
{
    return static_cast<const FixedLenBoolFieldItem&>(*this);
}

inline const FixedLenFloatFieldItem& Item::asFixedLenFloatFieldItem() const noexcept
{
    return static_cast<const FixedLenFloatFieldItem&>(*this);
}

inline const FixedLenSEnumFieldItem& Item::asFixedLenSEnumFieldItem() const noexcept
{
    return static_cast<const FixedLenSEnumFieldItem&>(*this);
}

inline const FixedLenSIntFieldItem& Item::asFixedLenSIntFieldItem() const noexcept
{
    return static_cast<const FixedLenSIntFieldItem&>(*this);
}

inline const FixedLenUEnumFieldItem& Item::asFixedLenUEnumFieldItem() const noexcept
{
    return static_cast<const FixedLenUEnumFieldItem&>(*this);
}

inline const FixedLenUIntFieldItem& Item::asFixedLenUIntFieldItem() const noexcept
{
    return static_cast<const FixedLenUIntFieldItem&>(*this);
}

inline const NullTerminatedStrFieldBeginItem&
Item::asNullTerminatedStrFieldBeginItem() const noexcept
{
    return static_cast<const NullTerminatedStrFieldBeginItem&>(*this);
}

inline const NullTerminatedStrFieldEndItem& Item::asNullTerminatedStrFieldEndItem() const noexcept
{
    return static_cast<const NullTerminatedStrFieldEndItem&>(*this);
}

inline const OptionalFieldBeginItem& Item::asOptionalFieldBeginItem() const noexcept
{
    return static_cast<const OptionalFieldBeginItem&>(*this);
}

inline const OptionalFieldEndItem& Item::asOptionalFieldEndItem() const noexcept
{
    return static_cast<const OptionalFieldEndItem&>(*this);
}

inline const OptionalFieldWithBoolSelBeginItem&
Item::asOptionalFieldWithBoolSelBeginItem() const noexcept
{
    return static_cast<const OptionalFieldWithBoolSelBeginItem&>(*this);
}

inline const OptionalFieldWithBoolSelEndItem&
Item::asOptionalFieldWithBoolSelEndItem() const noexcept
{
    return static_cast<const OptionalFieldWithBoolSelEndItem&>(*this);
}

inline const OptionalFieldWithSIntSelBeginItem&
Item::asOptionalFieldWithSIntSelBeginItem() const noexcept
{
    return static_cast<const OptionalFieldWithSIntSelBeginItem&>(*this);
}

inline const OptionalFieldWithSIntSelEndItem&
Item::asOptionalFieldWithSIntSelEndItem() const noexcept
{
    return static_cast<const OptionalFieldWithSIntSelEndItem&>(*this);
}

inline const OptionalFieldWithUIntSelBeginItem&
Item::asOptionalFieldWithUIntSelBeginItem() const noexcept
{
    return static_cast<const OptionalFieldWithUIntSelBeginItem&>(*this);
}

inline const OptionalFieldWithUIntSelEndItem&
Item::asOptionalFieldWithUIntSelEndItem() const noexcept
{
    return static_cast<const OptionalFieldWithUIntSelEndItem&>(*this);
}

inline const PktBeginItem& Item::asPktBeginItem() const noexcept
{
    return static_cast<const PktBeginItem&>(*this);
}

inline const PktContentBeginItem& Item::asPktContentBeginItem() const noexcept
{
    return static_cast<const PktContentBeginItem&>(*this);
}

inline const PktContentEndItem& Item::asPktContentEndItem() const noexcept
{
    return static_cast<const PktContentEndItem&>(*this);
}

inline const PktEndItem& Item::asPktEndItem() const noexcept
{
    return static_cast<const PktEndItem&>(*this);
}

inline const PktInfoItem& Item::asPktInfoItem() const noexcept
{
    return static_cast<const PktInfoItem&>(*this);
}

inline const PktMagicNumberItem& Item::asPktMagicNumberItem() const noexcept
{
    return static_cast<const PktMagicNumberItem&>(*this);
}

inline const ScopeBeginItem& Item::asScopeBeginItem() const noexcept
{
    return static_cast<const ScopeBeginItem&>(*this);
}

inline const ScopeEndItem& Item::asScopeEndItem() const noexcept
{
    return static_cast<const ScopeEndItem&>(*this);
}

inline const StaticLenArrayFieldBeginItem& Item::asStaticLenArrayFieldBeginItem() const noexcept
{
    return static_cast<const StaticLenArrayFieldBeginItem&>(*this);
}

inline const StaticLenArrayFieldEndItem& Item::asStaticLenArrayFieldEndItem() const noexcept
{
    return static_cast<const StaticLenArrayFieldEndItem&>(*this);
}

inline const StaticLenBlobFieldBeginItem& Item::asStaticLenBlobFieldBeginItem() const noexcept
{
    return static_cast<const StaticLenBlobFieldBeginItem&>(*this);
}

inline const StaticLenBlobFieldEndItem& Item::asStaticLenBlobFieldEndItem() const noexcept
{
    return static_cast<const StaticLenBlobFieldEndItem&>(*this);
}

inline const StaticLenStrFieldBeginItem& Item::asStaticLenStrFieldBeginItem() const noexcept
{
    return static_cast<const StaticLenStrFieldBeginItem&>(*this);
}

inline const StaticLenStrFieldEndItem& Item::asStaticLenStrFieldEndItem() const noexcept
{
    return static_cast<const StaticLenStrFieldEndItem&>(*this);
}

inline const StructFieldBeginItem& Item::asStructFieldBeginItem() const noexcept
{
    return static_cast<const StructFieldBeginItem&>(*this);
}

inline const StructFieldEndItem& Item::asStructFieldEndItem() const noexcept
{
    return static_cast<const StructFieldEndItem&>(*this);
}

inline const StrFieldSubstrItem& Item::asStrFieldSubstrItem() const noexcept
{
    return static_cast<const StrFieldSubstrItem&>(*this);
}

inline const MetadataStreamUuidItem& Item::asMetadataStreamUuidItem() const noexcept
{
    return static_cast<const MetadataStreamUuidItem&>(*this);
}

inline const VarLenSEnumFieldItem& Item::asVarLenSEnumFieldItem() const noexcept
{
    return static_cast<const VarLenSEnumFieldItem&>(*this);
}

inline const VarLenSIntFieldItem& Item::asVarLenSIntFieldItem() const noexcept
{
    return static_cast<const VarLenSIntFieldItem&>(*this);
}

inline const VarLenUEnumFieldItem& Item::asVarLenUEnumFieldItem() const noexcept
{
    return static_cast<const VarLenUEnumFieldItem&>(*this);
}

inline const VarLenUIntFieldItem& Item::asVarLenUIntFieldItem() const noexcept
{
    return static_cast<const VarLenUIntFieldItem&>(*this);
}

inline const VariantFieldBeginItem& Item::asVariantFieldBeginItem() const noexcept
{
    return static_cast<const VariantFieldBeginItem&>(*this);
}

inline const VariantFieldEndItem& Item::asVariantFieldEndItem() const noexcept
{
    return static_cast<const VariantFieldEndItem&>(*this);
}

inline const VariantFieldWithSIntSelBeginItem&
Item::asVariantFieldWithSIntSelBeginItem() const noexcept
{
    return static_cast<const VariantFieldWithSIntSelBeginItem&>(*this);
}

inline const VariantFieldWithSIntSelEndItem& Item::asVariantFieldWithSIntSelEndItem() const noexcept
{
    return static_cast<const VariantFieldWithSIntSelEndItem&>(*this);
}

inline const VariantFieldWithUIntSelBeginItem&
Item::asVariantFieldWithUIntSelBeginItem() const noexcept
{
    return static_cast<const VariantFieldWithUIntSelBeginItem&>(*this);
}

inline const VariantFieldWithUIntSelEndItem& Item::asVariantFieldWithUIntSelEndItem() const noexcept
{
    return static_cast<const VariantFieldWithUIntSelEndItem&>(*this);
}

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_ITEM_SEQ_ITEM_HPP */
