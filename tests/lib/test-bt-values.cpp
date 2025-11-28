/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2015 EfficiOS Inc. and Linux Foundation
 * Copyright (C) 2015 Philippe Proulx <pproulx@efficios.com>
 *
 * Babeltrace value objects tests
 */

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2/value.hpp"

#define CATCH_CONFIG_MAIN

#include "catch.hpp"

TEST_CASE("Null value")
{
    const bt2::NullValue nullVal;

    CHECK(nullVal.libObjPtr());
    CHECK(nullVal.isNull());

    SECTION("Getting a shared reference doesn't cause a crash")
    {
        const auto sharedNull = nullVal.shared();

        CHECK(sharedNull);
    }
}

namespace {

template <typename ValueT, typename RawValT>
void testScalarValue(const bt2::ValueType expectedType, const RawValT defaultVal,
                     const RawValT newVal, const RawValT initVal)
{
    SECTION("Default value")
    {
        const auto obj = ValueT::create();

        REQUIRE(obj);
        REQUIRE(obj->type() == expectedType);
        CHECK(**obj == defaultVal);
    }

    SECTION("Setting a value")
    {
        const auto obj = ValueT::create();

        REQUIRE(obj);
        REQUIRE(obj->type() == expectedType);
        obj->value(newVal);
        CHECK(**obj == newVal);
    }

    SECTION("Initial value")
    {
        const auto obj = ValueT::create(initVal);

        REQUIRE(obj);
        REQUIRE(obj->type() == expectedType);
        CHECK(**obj == initVal);
    }
}

} /* namespace */

TEST_CASE("Boolean value")
{
    testScalarValue<bt2::BoolValue>(bt2::ValueType::Bool, false, true, true);
}

TEST_CASE("Unsigned integer value")
{
    testScalarValue<bt2::UnsignedIntegerValue>(bt2::ValueType::UnsignedInteger, std::uint64_t {0},
                                               std::uint64_t {98765}, std::uint64_t {321456987});
}

TEST_CASE("Signed integer value")
{
    testScalarValue<bt2::SignedIntegerValue>(bt2::ValueType::SignedInteger, std::int64_t {0},
                                             std::int64_t {98765}, std::int64_t {-321456987});
}

TEST_CASE("Real value")
{
    testScalarValue<bt2::RealValue>(bt2::ValueType::Real, 0., -3.1416, 33.1649758);
}

TEST_CASE("String value")
{
    SECTION("Default value")
    {
        const auto obj = bt2::StringValue::create();

        REQUIRE(obj);
        REQUIRE(obj->type() == bt2::ValueType::String);
        CHECK(obj->value() == "");
    }

    SECTION("Setting a value")
    {
        const auto obj = bt2::StringValue::create();

        REQUIRE(obj);
        REQUIRE(obj->type() == bt2::ValueType::String);
        obj->value("hello worldz");
        CHECK(obj->value() == "hello worldz");
    }

    SECTION("Initial value")
    {
        const auto obj = bt2::createValue("initial value");

        REQUIRE(obj);
        REQUIRE(obj->type() == bt2::ValueType::String);
        CHECK(obj->value() == "initial value");
    }
}

TEST_CASE("Array value: initial state")
{
    const auto arrayObj = bt2::ArrayValue::create();

    REQUIRE(arrayObj);
    REQUIRE(arrayObj->isArray());
    CHECK(arrayObj->isEmpty());
    CHECK(arrayObj->length() == 0);
}

TEST_CASE("Array value: append and index value objects")
{
    const auto arrayObj = bt2::ArrayValue::create();

    arrayObj->append(*bt2::createValue(std::uint64_t {345}));
    arrayObj->append(*bt2::createValue(std::int64_t {-507}));
    arrayObj->append(*bt2::createValue(-17.45));
    arrayObj->append(*bt2::createValue(true));
    arrayObj->append(bt2::NullValue {});
    REQUIRE(arrayObj->length() == 5);
    REQUIRE((*arrayObj)[0].isUnsignedInteger());
    CHECK(*(*arrayObj)[0].asUnsignedInteger() == 345);
    REQUIRE((*arrayObj)[1].isSignedInteger());
    CHECK(*(*arrayObj)[1].asSignedInteger() == -507);
    REQUIRE((*arrayObj)[2].isReal());
    CHECK(*(*arrayObj)[2].asReal() == -17.45);
    REQUIRE((*arrayObj)[3].isBool());
    CHECK(*(*arrayObj)[3].asBool());
    CHECK((*arrayObj)[4].isNull());
}

TEST_CASE("Array value: set element by index")
{
    const auto arrayObj = bt2::ArrayValue::create();

    arrayObj->append(*bt2::createValue(std::int64_t {0}));
    arrayObj->append(*bt2::createValue(std::int64_t {0}));
    arrayObj->append(*bt2::createValue(std::int64_t {0}));
    REQUIRE(bt_value_array_set_element_by_index(
                arrayObj->libObjPtr(), 1, bt2::createValue(std::int64_t {1001})->libObjPtr()) ==
            BT_VALUE_ARRAY_SET_ELEMENT_BY_INDEX_STATUS_OK);
    REQUIRE((*arrayObj)[1].isSignedInteger());
    CHECK(*(*arrayObj)[1].asSignedInteger() == 1001);
}

TEST_CASE("Array value: append raw values")
{
    const auto arrayObj = bt2::ArrayValue::create();

    arrayObj->append(false);
    arrayObj->append(std::uint64_t {98765});
    arrayObj->append(std::int64_t {-10101});
    arrayObj->append(2.49578);
    arrayObj->append("bt_value");
    REQUIRE(arrayObj->length() == 5);
    REQUIRE_FALSE(arrayObj->isEmpty());
    REQUIRE((*arrayObj)[0].isBool());
    CHECK_FALSE(*(*arrayObj)[0].asBool());
    REQUIRE((*arrayObj)[1].isUnsignedInteger());
    CHECK(*(*arrayObj)[1].asUnsignedInteger() == 98765);
    REQUIRE((*arrayObj)[2].isSignedInteger());
    CHECK(*(*arrayObj)[2].asSignedInteger() == -10101);
    REQUIRE((*arrayObj)[3].isReal());
    CHECK(*(*arrayObj)[3].asReal() == 2.49578);
    REQUIRE((*arrayObj)[4].isString());
    CHECK((*arrayObj)[4].asString().value() == "bt_value");
}

TEST_CASE("Array value: append empty containers")
{
    const auto arrayObj = bt2::ArrayValue::create();

    {
        const auto emptyArray = arrayObj->appendEmptyArray();

        CHECK(emptyArray.isArray());
        CHECK(emptyArray.isEmpty());
    }

    {
        const auto emptyMap = arrayObj->appendEmptyMap();

        CHECK(emptyMap.isMap());
        CHECK(emptyMap.isEmpty());
    }

    REQUIRE(arrayObj->length() == 2);
    REQUIRE((*arrayObj)[0].isArray());
    CHECK((*arrayObj)[0].asArray().isEmpty());
    REQUIRE((*arrayObj)[1].isMap());
    CHECK((*arrayObj)[1].asMap().isEmpty());
}

TEST_CASE("Map value: initial state")
{
    const auto mapObj = bt2::MapValue::create();

    REQUIRE(mapObj);
    REQUIRE(mapObj->isMap());
    CHECK(mapObj->isEmpty());
    CHECK(mapObj->length() == 0);
}

TEST_CASE("Map value: insert and access value objects directly")
{
    const auto mapObj = bt2::MapValue::create();

    mapObj->insert("uint", *bt2::createValue(std::uint64_t {19457}));
    mapObj->insert("int", *bt2::createValue(std::int64_t {-12345}));
    mapObj->insert("real", *bt2::createValue(5.444));
    mapObj->insert("bool", *bt2::createValue(false));
    mapObj->insert("null", bt2::NullValue {});
    CHECK(mapObj->length() == 5);

    /* Overwrite existing key */
    mapObj->insert("bool", *bt2::createValue(true));
    CHECK(mapObj->length() == 5);

    /* Non-existing key returns empty optional */
    CHECK_FALSE((*mapObj)["life"]);

    /* Access and verify each element */
    {
        const auto obj = (*mapObj)["uint"];

        REQUIRE(obj);
        REQUIRE(obj->isUnsignedInteger());
        CHECK(*obj->asUnsignedInteger() == 19457);
    }

    {
        const auto obj = (*mapObj)["int"];

        REQUIRE(obj);
        REQUIRE(obj->isSignedInteger());
        CHECK(*obj->asSignedInteger() == -12345);
    }

    {
        const auto obj = (*mapObj)["real"];

        REQUIRE(obj);
        REQUIRE(obj->isReal());
        CHECK(*obj->asReal() == 5.444);
    }

    {
        const auto obj = (*mapObj)["bool"];

        REQUIRE(obj);
        REQUIRE(obj->isBool());
        CHECK(*obj->asBool());
    }

    {
        const auto obj = (*mapObj)["null"];

        REQUIRE(obj);
        CHECK(obj->isNull());
    }
}

TEST_CASE("Map value: insert raw values")
{
    const auto mapObj = bt2::MapValue::create();

    mapObj->insert("bool", true);
    mapObj->insert("int", std::int64_t {98765});
    mapObj->insert("real", -49.0001);
    mapObj->insert("string", "bt_value");
    CHECK(mapObj->length() == 4);
    REQUIRE((*mapObj)["bool"]->isBool());
    CHECK(*(*mapObj)["bool"]->asBool());
    REQUIRE((*mapObj)["int"]->isSignedInteger());
    CHECK(*(*mapObj)["int"]->asSignedInteger() == 98765);
    REQUIRE((*mapObj)["real"]->isReal());
    CHECK(*(*mapObj)["real"]->asReal() == -49.0001);
    REQUIRE((*mapObj)["string"]->isString());
    CHECK((*mapObj)["string"]->asString().value() == "bt_value");
}

TEST_CASE("Map value: insert empty containers")
{
    const auto mapObj = bt2::MapValue::create();

    {
        const auto emptyArray = mapObj->insertEmptyArray("array");

        REQUIRE(emptyArray.isArray());
        CHECK(emptyArray.isEmpty());
    }

    {
        const auto emptyMap = mapObj->insertEmptyMap("map");

        REQUIRE(emptyMap.isMap());
        CHECK(emptyMap.isEmpty());
    }

    CHECK(mapObj->length() == 2);
    REQUIRE((*mapObj)["array"]->isArray());
    CHECK((*mapObj)["array"]->asArray().isEmpty());
    REQUIRE((*mapObj)["map"]->isMap());
    CHECK((*mapObj)["map"]->asMap().isEmpty());
}

TEST_CASE("Map value: bt2::MapValue::hasEntry() works")
{
    const auto mapObj = bt2::MapValue::create();

    mapObj->insert("key1", true);
    mapObj->insert("key2", std::int64_t {42});
    CHECK(mapObj->hasEntry("key1"));
    CHECK(mapObj->hasEntry("key2"));
    CHECK_FALSE(mapObj->hasEntry("nonexistent"));
}

TEST_CASE("Map value: bt2::MapValue::forEach() works")
{
    const auto mapObj = bt2::MapValue::create();

    mapObj->insert("bool", true);
    mapObj->insert("int", std::int64_t {42});
    mapObj->insert("string", "hello");

    std::size_t count = 0;
    bool foundBool = false;
    bool foundInt = false;
    bool foundString = false;

    mapObj->forEach([&](const bt2c::CStringView key, const bt2::Value val) {
        ++count;

        if (key == "bool") {
            REQUIRE(val.isBool());
            CHECK(*val.asBool());
            foundBool = true;
        } else if (key == "int") {
            REQUIRE(val.isSignedInteger());
            CHECK(*val.asSignedInteger() == 42);
            foundInt = true;
        } else if (key == "string") {
            REQUIRE(val.isString());
            CHECK(val.asString().value() == "hello");
            foundString = true;
        }
    });

    CHECK(count == 3);
    CHECK(foundBool);
    CHECK(foundInt);
    CHECK(foundString);
}

TEST_CASE("Map value: extend")
{
    const auto baseMap = bt2::MapValue::create();

    baseMap->insert("file", true);
    baseMap->insert("edit", false);
    baseMap->insert("selection", std::int64_t {17});
    baseMap->insert("find", std::int64_t {-34});

    const auto extensionMap = bt2::MapValue::create();

    extensionMap->insert("edit", true);
    extensionMap->insert("find", std::int64_t {101});
    extensionMap->insert("project", -404.0);

    const auto extendedMap = baseMap->copy();

    REQUIRE(extendedMap);
    REQUIRE(bt_value_map_extend(extendedMap->libObjPtr(), extensionMap->libObjPtr()) ==
            BT_VALUE_MAP_EXTEND_STATUS_OK);
    CHECK(extendedMap->asMap().length() == 5);

    /* `file` from base */
    REQUIRE((*extendedMap)["file"]);
    REQUIRE((*extendedMap)["file"]->isBool());
    CHECK(*(*extendedMap)["file"]->asBool() == *(*baseMap)["file"]->asBool());

    /* `edit` from extension (overwritten) */
    REQUIRE((*extendedMap)["edit"]);
    REQUIRE((*extendedMap)["edit"]->isBool());
    CHECK(*(*extendedMap)["edit"]->asBool() == *(*extensionMap)["edit"]->asBool());

    /* `selection` from base */
    REQUIRE((*extendedMap)["selection"]);
    REQUIRE((*extendedMap)["selection"]->isSignedInteger());
    CHECK(*(*extendedMap)["selection"]->asSignedInteger() ==
          *(*baseMap)["selection"]->asSignedInteger());

    /* `find` from extension (overwritten) */
    REQUIRE((*extendedMap)["find"]);
    REQUIRE((*extendedMap)["find"]->isSignedInteger());
    CHECK(*(*extendedMap)["find"]->asSignedInteger() ==
          *(*extensionMap)["find"]->asSignedInteger());

    /* `project` from extension (new) */
    REQUIRE((*extendedMap)["project"]);
    REQUIRE((*extendedMap)["project"]->isReal());
    CHECK(*(*extendedMap)["project"]->asReal() == *(*extensionMap)["project"]->asReal());
}

TEST_CASE("Value equality: null")
{
    CHECK(bt2::NullValue {} == bt2::NullValue {});
}

namespace {

template <typename RawValT>
void testScalarValueEquality(const RawValT val1, const RawValT val2)
{
    const auto obj1 = bt2::createValue(val1);
    const auto obj2 = bt2::createValue(val2);
    const auto obj3 = bt2::createValue(val1);

    CHECK(bt2::NullValue {} != *obj1);
    CHECK(*obj1 != *obj2);
    CHECK(*obj1 == *obj3);
}

} /* namespace */

TEST_CASE("Value equality: boolean")
{
    testScalarValueEquality(false, true);
}

TEST_CASE("Value equality: unsigned integer")
{
    testScalarValueEquality(std::uint64_t {10}, std::uint64_t {23});
}

TEST_CASE("Value equality: signed integer")
{
    testScalarValueEquality(std::int64_t {10}, std::int64_t {-23});
}

TEST_CASE("Value equality: real")
{
    testScalarValueEquality(17.38, -14.23);
}

TEST_CASE("Value equality: string")
{
    testScalarValueEquality("hello", "bt_value");
}

TEST_CASE("Value equality: array")
{
    const auto array1 = bt2::ArrayValue::create();
    const auto array2 = bt2::ArrayValue::create();

    CHECK(*array1 == *array2);

    array1->append(std::int64_t {23});
    array1->append(14.2);
    array1->append(false);
    array2->append(14.2);
    array2->append(std::int64_t {23});
    array2->append(false);

    const auto array3 = bt2::ArrayValue::create();

    array3->append(std::int64_t {23});
    array3->append(14.2);
    array3->append(false);
    CHECK(bt2::NullValue {} != *array1);
    CHECK(*array1 != *array2);
    CHECK(*array1 == *array3);
}

TEST_CASE("Value equality: map")
{
    const auto map1 = bt2::MapValue::create();
    const auto map2 = bt2::MapValue::create();

    CHECK(*map1 == *map2);
    map1->insert("one", std::int64_t {23});
    map1->insert("two", 14.2);
    map1->insert("three", false);
    map2->insert("one", 14.2);
    map2->insert("two", std::int64_t {23});
    map2->insert("three", false);

    const auto map3 = bt2::MapValue::create();

    map3->insert("three", false);
    map3->insert("one", std::int64_t {23});
    map3->insert("two", 14.2);
    CHECK(bt2::NullValue {} != *map1);
    CHECK(*map1 != *map2);
    CHECK(*map1 == *map3);
}

TEST_CASE("Value copy")
{
    /*
     * Here's the deal here. If we make sure that each value object
     * of our deep copy has a different address than its source, and
     * that operator==() returns true for the top-level value object,
     * taking into account that we test the correctness of operator==()
     * elsewhere, then the deep copy is a success.
     */
    const auto boolObj = bt2::createValue(true);
    const auto unsignedIntegerObj = bt2::createValue(std::uint64_t {23});
    const auto signedIntegerObj = bt2::createValue(std::int64_t {-47});
    const auto realObj = bt2::createValue(-3.1416);
    const auto stringObj = bt2::createValue("test");
    auto arrayObj = bt2::ArrayValue::create();
    auto mapObj = bt2::MapValue::create();

    arrayObj->append(*boolObj);
    arrayObj->append(*unsignedIntegerObj);
    arrayObj->append(*signedIntegerObj);
    arrayObj->append(*realObj);
    arrayObj->append(bt2::NullValue {});

    mapObj->insert("array", *arrayObj);
    mapObj->insert("string", *stringObj);

    const auto mapCopyObj = mapObj->copy();

    REQUIRE(mapCopyObj);
    CHECK(mapObj->libObjPtr() != mapCopyObj->libObjPtr());

    {
        const auto stringCopyObj = (*mapCopyObj)["string"];

        REQUIRE(stringCopyObj);
        CHECK(stringCopyObj->libObjPtr() != stringObj->libObjPtr());
    }

    const auto arrayCopyObj = (*mapCopyObj)["array"];

    REQUIRE(arrayCopyObj);
    CHECK(arrayCopyObj->libObjPtr() != arrayObj->libObjPtr());
    CHECK(arrayCopyObj->asArray()[0].libObjPtr() != boolObj->libObjPtr());
    CHECK(arrayCopyObj->asArray()[1].libObjPtr() != unsignedIntegerObj->libObjPtr());
    CHECK(arrayCopyObj->asArray()[2].libObjPtr() != signedIntegerObj->libObjPtr());
    CHECK(arrayCopyObj->asArray()[3].libObjPtr() != realObj->libObjPtr());
    CHECK(arrayCopyObj->asArray()[4].libObjPtr() == bt_value_null);
    CHECK(*mapObj == *mapCopyObj);
}
