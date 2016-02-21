#ifndef BABELTRACE_HPP
#define BABELTRACE_HPP

#include <stdint.h>
#include <stddef.h>
#include <stdexcept>
#include <string>
#include <babeltrace/ref.h>
#include <babeltrace/ctf-ir/field-types.h>
#include <babeltrace/ctf-ir/fields.h>

namespace bt {

class Error : public std::runtime_error
{
public:
    Error() :
        std::runtime_error("Babeltrace error")
    {
    }
};

class Object
{
protected:
    Object(void *object) :
        _object(object)
    {
        if (!object) {
            throw Error();
        }
    }

public:
    virtual ~Object()
    {
        this->putRef();
    }

    Object *getRef()
    {
        ::bt_get(_object);

        return this;
    }

    void putRef() const
    {
        ::bt_put(_object);
    }

protected:
    void *_object;
};

namespace ctf {

class Field;

class FieldType : public Object
{
protected:
    FieldType(::bt_ctf_field_type *fieldType) :
        Object(fieldType),
        _fieldType(fieldType)
    {
    }

public:
    enum TypeId {
        TYPE_ID_UNKNOWN     = BT_CTF_TYPE_ID_UNKNOWN,
        TYPE_ID_INTEGER     = BT_CTF_TYPE_ID_INTEGER,
        TYPE_ID_FLOAT       = BT_CTF_TYPE_ID_FLOAT,
        TYPE_ID_ENUM        = BT_CTF_TYPE_ID_ENUM,
        TYPE_ID_STRING      = BT_CTF_TYPE_ID_STRING,
        TYPE_ID_STRUCT      = BT_CTF_TYPE_ID_STRUCT,
        TYPE_ID_VARIANT     = BT_CTF_TYPE_ID_VARIANT,
        TYPE_ID_ARRAY       = BT_CTF_TYPE_ID_ARRAY,
        TYPE_ID_SEQUENCE    = BT_CTF_TYPE_ID_SEQUENCE,
    };

    enum ByteOrder {
        BYTE_ORDER_UNKNOWN          = BT_CTF_BYTE_ORDER_UNKNOWN,
        BYTE_ORDER_NATIVE           = BT_CTF_BYTE_ORDER_NATIVE,
        BYTE_ORDER_LITTLE_ENDIAN    = BT_CTF_BYTE_ORDER_LITTLE_ENDIAN,
        BYTE_ORDER_BIG_ENDIAN       = BT_CTF_BYTE_ORDER_BIG_ENDIAN,
        BYTE_ORDER_NETWORK          = BT_CTF_BYTE_ORDER_NETWORK,
    };

    enum StringEncoding {
        STRING_ENCODING_NONE    = BT_CTF_STRING_ENCODING_NONE,
        STRING_ENCODING_UTF8    = BT_CTF_STRING_ENCODING_UTF8,
        STRING_ENCODING_ASCII   = BT_CTF_STRING_ENCODING_ASCII,
        STRING_ENCODING_UNKNOWN = BT_CTF_STRING_ENCODING_UNKNOWN,
    };

public:
    ::bt_ctf_field_type *getNativeFieldType() const
    {
        return _fieldType;
    }

    TypeId getTypeId() const
    {
        return static_cast<TypeId>(::bt_ctf_field_type_get_type_id(_fieldType));
    }

    size_t getAlignment() const
    {
        int alignment = ::bt_ctf_field_type_get_alignment(_fieldType);

        if (alignment < 0) {
            throw Error();
        }

        return static_cast<size_t>(alignment);
    }

    void setAlignment(size_t alignment) const
    {
        int ret = ::bt_ctf_field_type_set_alignment(_fieldType, alignment);

        if (ret) {
            throw Error();
        }
    }

    bool isInteger() const
    {
        return ::bt_ctf_field_type_is_integer(_fieldType);
    }

    bool isFloatingPoint() const
    {
        return ::bt_ctf_field_type_is_floating_point(_fieldType);
    }

    bool isString() const
    {
        return ::bt_ctf_field_type_is_string(_fieldType);
    }

    bool isEnumeration() const
    {
        return ::bt_ctf_field_type_is_enumeration(_fieldType);
    }

    bool isArray() const
    {
        return ::bt_ctf_field_type_is_array(_fieldType);
    }

    bool isSequence() const
    {
        return ::bt_ctf_field_type_is_sequence(_fieldType);
    }

    bool isStructure() const
    {
        return ::bt_ctf_field_type_is_structure(_fieldType);
    }

    bool isVariant() const
    {
        return ::bt_ctf_field_type_is_variant(_fieldType);
    }

    bool operator==(const FieldType &otherFieldType)
    {
        int ret = ::bt_ctf_field_type_compare(_fieldType,
            otherFieldType._fieldType);

        if (ret < 0) {
            throw Error();
        }

        return ret == 0;
    }

    Field *createField() const;

protected:
    ::bt_ctf_field_type *_fieldType;
};

class EnumerationFieldType;

class IntegerFieldType : public FieldType
{
    friend class Field;
    friend class EnumerationFieldType;

public:
    enum Base {
        BASE_UNKNOWN        = BT_CTF_INTEGER_BASE_UNKNOWN,
        BASE_BINARY         = BT_CTF_INTEGER_BASE_BINARY,
        BASE_OCTAL          = BT_CTF_INTEGER_BASE_OCTAL,
        BASE_DECIMAL        = BT_CTF_INTEGER_BASE_DECIMAL,
        BASE_HEXADECIMAL    = BT_CTF_INTEGER_BASE_HEXADECIMAL,
    };

public:
    explicit IntegerFieldType(size_t size) :
        FieldType(::bt_ctf_field_type_integer_create(static_cast<int>(size)))
    {
    }

    IntegerFieldType(size_t size, bool isSigned) :
        FieldType(::bt_ctf_field_type_integer_create(static_cast<int>(size)))
    {
        this->setSigned(isSigned);
    }

    IntegerFieldType(size_t size, ByteOrder byteOrder) :
        FieldType(::bt_ctf_field_type_integer_create(static_cast<int>(size)))
    {
        this->setByteOrder(byteOrder);
    }

    IntegerFieldType(size_t size, bool isSigned, ByteOrder byteOrder) :
        FieldType(::bt_ctf_field_type_integer_create(static_cast<int>(size)))
    {
        this->setSigned(isSigned);
        this->setByteOrder(byteOrder);
    }

    size_t getSize() const
    {
        int size = ::bt_ctf_field_type_integer_get_size(_fieldType);

        if (size < 0) {
            throw Error();
        }

        return static_cast<size_t>(size);
    }

    bool isSigned() const
    {
        int isSigned =
            ::bt_ctf_field_type_integer_get_signed(_fieldType);

        if (isSigned < 0) {
            throw Error();
        }

        return isSigned;
    }

    void setSigned(bool isSigned)
    {
        int ret = ::bt_ctf_field_type_integer_set_signed(_fieldType, isSigned);

        if (ret) {
            throw Error();
        }
    }

    Base getBase() const
    {
        ::bt_ctf_integer_base base =
            ::bt_ctf_field_type_integer_get_base(_fieldType);

        if (base == ::BT_CTF_INTEGER_BASE_UNKNOWN) {
            throw Error();
        }

        return static_cast<Base>(base);
    }

    void setBase(Base base)
    {
        int ret = ::bt_ctf_field_type_integer_set_base(_fieldType,
            static_cast<::bt_ctf_integer_base>(base));

        if (ret) {
            throw Error();
        }
    }

    StringEncoding getEncoding() const
    {
        ::bt_ctf_string_encoding encoding =
            ::bt_ctf_field_type_integer_get_encoding(_fieldType);

        if (encoding == ::BT_CTF_STRING_ENCODING_UNKNOWN) {
            throw Error();
        }

        return static_cast<StringEncoding>(encoding);
    }

    void setEncoding(StringEncoding encoding)
    {
        int ret = ::bt_ctf_field_type_integer_set_encoding(_fieldType,
            static_cast<::bt_ctf_string_encoding>(encoding));

        if (ret) {
            throw Error();
        }
    }

    ByteOrder getByteOrder() const
    {
        ::bt_ctf_byte_order byteOrder =
            ::bt_ctf_field_type_get_byte_order(_fieldType);

        if (byteOrder == ::BT_CTF_BYTE_ORDER_UNKNOWN) {
            throw Error();
        }

        return static_cast<ByteOrder>(byteOrder);
    }

    void setByteOrder(ByteOrder byteOrder)
    {
        int ret = ::bt_ctf_field_type_set_byte_order(_fieldType,
            static_cast<::bt_ctf_byte_order>(byteOrder));

        if (ret) {
            throw Error();
        }
    }

private:
    explicit IntegerFieldType(::bt_ctf_field_type *fieldType) :
        FieldType(fieldType)
    {
    }
};

class FloatingPointFieldType : public FieldType
{
    friend class Field;

public:
    FloatingPointFieldType() :
        FieldType(::bt_ctf_field_type_floating_point_create())
    {
    }

    explicit FloatingPointFieldType(ByteOrder byteOrder) :
        FieldType(::bt_ctf_field_type_floating_point_create())
    {
        this->setByteOrder(byteOrder);
    }

    FloatingPointFieldType(size_t exponentSize, size_t mantissaSize) :
        FieldType(::bt_ctf_field_type_floating_point_create())
    {
        this->setSize(exponentSize, mantissaSize);
    }

    FloatingPointFieldType(size_t exponentSize, size_t mantissaSize,
                           ByteOrder byteOrder) :
        FieldType(::bt_ctf_field_type_floating_point_create())
    {
        this->setSize(exponentSize, mantissaSize);
        this->setByteOrder(byteOrder);
    }

    size_t getExponentSize() const
    {
        int size = ::bt_ctf_field_type_floating_point_get_exponent_digits(
            _fieldType);

        if (size < 0) {
            throw Error();
        }

        return static_cast<size_t>(size);
    }

    void setExponentSize(size_t size) const
    {
        int ret = ::bt_ctf_field_type_floating_point_set_exponent_digits(
            _fieldType, size);

        if (ret) {
            throw Error();
        }
    }

    size_t getMantissaSize() const
    {
        int size = ::bt_ctf_field_type_floating_point_get_mantissa_digits(
            _fieldType);

        if (size < 0) {
            throw Error();
        }

        return static_cast<size_t>(size);
    }

    void setMantissaSize(size_t size) const
    {
        int ret = ::bt_ctf_field_type_floating_point_set_mantissa_digits(
            _fieldType, size);

        if (ret) {
            throw Error();
        }
    }

    void setSize(size_t exponentSize, size_t mantissaSize)
    {
        this->setExponentSize(exponentSize);
        this->setMantissaSize(mantissaSize);
    }

    ByteOrder getByteOrder() const
    {
        ::bt_ctf_byte_order byteOrder =
            ::bt_ctf_field_type_get_byte_order(_fieldType);

        if (byteOrder == ::BT_CTF_BYTE_ORDER_UNKNOWN) {
            throw Error();
        }

        return static_cast<ByteOrder>(byteOrder);
    }

    void setByteOrder(ByteOrder byteOrder)
    {
        int ret = ::bt_ctf_field_type_set_byte_order(_fieldType,
            static_cast<::bt_ctf_byte_order>(byteOrder));

        if (ret) {
            throw Error();
        }
    }

private:
    explicit FloatingPointFieldType(::bt_ctf_field_type *fieldType) :
        FieldType(fieldType)
    {
    }
};

class StringFieldType : public FieldType
{
    friend class Field;

public:
    StringFieldType() :
        FieldType(::bt_ctf_field_type_string_create())
    {
    }

    StringFieldType(StringEncoding encoding) :
        FieldType(::bt_ctf_field_type_string_create())
    {
        this->setEncoding(encoding);
    }

    StringEncoding getEncoding() const
    {
        ::bt_ctf_string_encoding encoding =
            ::bt_ctf_field_type_string_get_encoding(_fieldType);

        if (encoding == ::BT_CTF_STRING_ENCODING_UNKNOWN) {
            throw Error();
        }

        return static_cast<StringEncoding>(encoding);
    }

    void setEncoding(StringEncoding encoding)
    {
        int ret = ::bt_ctf_field_type_string_set_encoding(_fieldType,
            static_cast<::bt_ctf_string_encoding>(encoding));

        if (ret) {
            throw Error();
        }
    }

private:
    explicit StringFieldType(::bt_ctf_field_type *fieldType) :
        FieldType(fieldType)
    {
    }
};

class EnumerationFieldType : public FieldType
{
    friend class Field;

public:
    struct Range
    {
        int64_t begin;
        int64_t end;
    };

public:
    EnumerationFieldType(IntegerFieldType *containerType) :
        FieldType(::bt_ctf_field_type_enumeration_create(
            containerType->getNativeFieldType()))
    {
    }

    IntegerFieldType *getContainerType() const
    {
        ::bt_ctf_field_type *containerType =
            ::bt_ctf_field_type_enumeration_get_container_type(_fieldType);

        if (!containerType) {
            throw Error();
        }

        return new IntegerFieldType(containerType);
    }

    void addMapping(const std::string &label, int64_t begin, int64_t end)
    {
        int ret = ::bt_ctf_field_type_enumeration_add_mapping(_fieldType,
            label.c_str(), begin, end);

        if (ret) {
            throw Error();
        }
    }

    void addMapping(const std::string &label, const Range &range)
    {
        this->addMapping(label, range.begin, range.end);
    }

    size_t getMappingCount() const
    {
        int mappingCount = ::bt_ctf_field_type_enumeration_get_mapping_count(
            _fieldType);

        if (mappingCount < 0) {
            throw Error();
        }

        return static_cast<size_t>(mappingCount);
    }

    bool hasLabel(const std::string &label) const
    {
        return ::bt_ctf_field_type_enumeration_get_mapping_index_by_name(
            _fieldType, label.c_str()) >= 0;
    }

    Range rangeOfLabel(const std::string &label) const
    {
        int index = ::bt_ctf_field_type_enumeration_get_mapping_index_by_name(
            _fieldType, label.c_str());

        if (index < 0) {
            throw Error();
        }

        Range range;
        const char *labelRet;
        int ret = ::bt_ctf_field_type_enumeration_get_mapping(_fieldType, index,
            &labelRet, &range.begin, &range.end);

        if (ret) {
            throw Error();
        }

        return range;
    }

private:
    explicit EnumerationFieldType(::bt_ctf_field_type *fieldType) :
        FieldType(fieldType)
    {
    }
};

class Field : public Object
{
    friend class FieldType;

private:
    Field(::bt_ctf_field *field) :
        Object(field),
        _field(field)
    {
    }

public:
    ::bt_ctf_field *getNativeField() const
    {
        return _field;
    }

    FieldType *getType() const
    {
        ::bt_ctf_field_type *fieldType = ::bt_ctf_field_get_type(_field);

        if (!fieldType) {
            throw Error();
        }

        ::bt_ctf_type_id typeId = ::bt_ctf_field_type_get_type_id(fieldType);

        if (typeId == ::BT_CTF_TYPE_ID_UNKNOWN) {
            throw Error();
        }

        switch (typeId) {
        case ::BT_CTF_TYPE_ID_INTEGER:
            return new IntegerFieldType(fieldType);
        case ::BT_CTF_TYPE_ID_FLOAT:
            return new FloatingPointFieldType(fieldType);
        case ::BT_CTF_TYPE_ID_ENUM:
            return new EnumerationFieldType(fieldType);
        case ::BT_CTF_TYPE_ID_STRING:
            return new StringFieldType(fieldType);
        case ::BT_CTF_TYPE_ID_STRUCT:
        case ::BT_CTF_TYPE_ID_VARIANT:
        case ::BT_CTF_TYPE_ID_ARRAY:
        case ::BT_CTF_TYPE_ID_SEQUENCE:
        default:
            // TODO
            throw Error();
            break;
        }
    }

protected:
    ::bt_ctf_field *_field;
};

Field *FieldType::createField() const
{
    ::bt_ctf_field *field = ::bt_ctf_field_create(_fieldType);

    if (!field) {
        throw Error();
    }

    return new Field(field);
}

} // namespace ctf
} // namespace bt

#endif // BABELTRACE_HPP
