/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 EfficiOS Inc. and Linux Foundation
 */

#ifndef _CTF_SRC_PKT_PROPS_HPP
#define _CTF_SRC_PKT_PROPS_HPP

#include <cstdint>

#include "cpp-common/optional.hpp"
#include "cpp-common/data-len.hpp"

#include "metadata/ctf-ir.hpp"
#include "item-seq/medium.hpp"

namespace ctf {
namespace src {

struct PktProps final
{
    nonstd::optional<bt2_common::DataLen> expectedTotalLen;
    nonstd::optional<bt2_common::DataLen> expectedContentLen;
    const DataStreamCls *dataStreamCls;
    nonstd::optional<unsigned long long> dataStreamId;

    struct
    {
        nonstd::optional<unsigned long long> discEventRecordCounter;
        nonstd::optional<unsigned long long> beginDefClk;
        nonstd::optional<unsigned long long> endDefClk;
    } snapshots;
};

/*
 * Extract packet properties at offset.
 */
PktProps readPktProps(const TraceCls& traceCls, Medium::UP medium, bt2_common::DataLen pktOffset);

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_PKT_PROPS_HPP */
