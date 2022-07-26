/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Philippe Proulx <pproulx@efficios.com>
 */

#include <babeltrace2/babeltrace.h>

#include "ctf-meta-configure-ir-trace.hpp"
#include "cpp-common/uuid.hpp"

BT_HIDDEN
void ctf_trace_class_configure_ir_trace(struct ctf_trace_class *tc, bt2::Trace ir_trace)
{
    uint64_t i;

    BT_ASSERT(tc);

    if (tc->is_uuid_set) {
        bt2_common::Uuid uuid {tc->uuid};
        ir_trace.uuid(uuid);
    }

    for (i = 0; i < tc->env_entries->len; i++) {
        struct ctf_trace_class_env_entry *env_entry =
            ctf_trace_class_borrow_env_entry_by_index(tc, i);

        switch (env_entry->type) {
        case CTF_TRACE_CLASS_ENV_ENTRY_TYPE_INT:
            ir_trace.environmentEntry(env_entry->name->str, env_entry->value.i);
            break;
        case CTF_TRACE_CLASS_ENV_ENTRY_TYPE_STR:
            ir_trace.environmentEntry(env_entry->name->str, env_entry->value.str->str);
            break;
        default:
            bt_common_abort();
        }
    }
}

BT_HIDDEN
void ctf_trace_class_configure_ir_trace(const ctf::src::TraceCls& tc, bt2::Trace irTrace)
{
    if (tc.uuid()) {
        irTrace.uuid(*tc.uuid());
    }

    if (tc.env()) {
        tc.env()->forEach([&irTrace](const bpstd::string_view name, bt2::ConstValue val) {
            switch (val.type()) {
            case bt2::ValueType::SIGNED_INTEGER:
                irTrace.environmentEntry(name.c_str(), val.asSignedInteger().value());
                break;

            case bt2::ValueType::STRING:
                irTrace.environmentEntry(name.c_str(), val.asString().value().c_str());
                break;

            default:
                bt_common_abort();
            }
        });
    }
}
