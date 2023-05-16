/*
 * Copyright (c) 2022-2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _CTF_SRC_METADATA_JSON_CTF_2_FC_BUILDER_HPP
#define _CTF_SRC_METADATA_JSON_CTF_2_FC_BUILDER_HPP

#include <unordered_map>
#include <string>

#include "cpp-common/json-val.hpp"
#include "cpp-common/log-cfg.hpp"
#include "cpp-common/text-loc.hpp"
#include "../ctf-ir.hpp"
#include "../../../metadata/json/strings.hpp"
#include "logging-obj.hpp"

namespace ctf {
namespace src {

/*
 * Field class builder for CTF 2.
 *
 * An instance keeps a map of field class alias names to field class
 * aliases.
 *
 * Build a field class from an equivalent CTF 2 JSON value with
 * buildFcFromJsonVal().
 *
 * Add a field class alias with addFcAlias().
 */
class Ctf2FcBuilder final : public LoggingObj
{
public:
    /*
     * Builds a field class builder without any initial field class
     * alias.
     */
    explicit Ctf2FcBuilder(const bt2_common::LogCfg& logCfg,
                           bt2_common::TextLocStrFmt textLocStrFmt);

    /*
     * Builds and returns a field class from the CTF 2 JSON (string
     * (alias) or object) value `jsonFc`, or appends a cause to the
     * error of the current thread and throws `bt2_common::Error` on
     * error.
     */
    Fc::UP buildFcFromJsonVal(const bt2_common::JsonVal& jsonFc) const;

    /*
     * Adds a field class alias `fc` named `name`, or appends a cause to
     * the error of the current thread and throws `bt2_common::Error` on
     * error.
     */
    void addFcAlias(std::string name, Fc::UP fc, const bt2_common::TextLoc& nameLoc);

private:
    /*
     * Returns a clone of the field class alias named `name`.
     */
    Fc::UP _aliasedFc(const std::string& name, const bt2_common::TextLoc& loc) const;

    /*
     * Creates and returns an array field class from the JSON array
     * field class value `jsonFc` and the other parameters.
     */
    Fc::UP _fcFromJsonArrayFc(const bt2_common::JsonObjVal& jsonFc, const std::string& type,
                              ir::OptUserAttrs&& userAttrs) const;

    /*
     * Creates and returns a structure field class from the JSON
     * structure field class value `jsonFc` and from `userAttrs`.
     */
    Fc::UP _fcFromJsonStructFc(const bt2_common::JsonObjVal& jsonFc,
                               ir::OptUserAttrs&& userAttrs) const;

    /*
     * Creates and returns an optional field class from the JSON
     * optional field class value `jsonFc` and from `userAttrs`.
     */
    Fc::UP _fcFromJsonOptionalFc(const bt2_common::JsonObjVal& jsonFc,
                                 ir::OptUserAttrs&& userAttrs) const;

    /*
     * Creates and returns a variant field class from the JSON variant
     * field class value `jsonFc` and from `userAttrs`.
     */
    Fc::UP _fcFromJsonVariantFc(const bt2_common::JsonObjVal& jsonFc,
                                ir::OptUserAttrs&& userAttrs) const;

    /* Map of alias name to aliased field classes */
    std::unordered_map<std::string, Fc::UP> _mFcAliases;
};

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_JSON_CTF_2_FC_BUILDER_HPP */
