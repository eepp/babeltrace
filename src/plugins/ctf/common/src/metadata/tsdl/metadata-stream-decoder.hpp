/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#ifndef _CTF_SRC_METADATA_TSDL_METADATA_STREAM_DECODER_HPP
#define _CTF_SRC_METADATA_TSDL_METADATA_STREAM_DECODER_HPP

#include "cpp-common/optional.hpp"
#include "cpp-common/data-len.hpp"
#include "../../../metadata/ctf-ir.hpp"
#include "cpp-common/log-cfg.hpp"

namespace ctf {
namespace src {

/*
 * Packet information of a metadata stream.
 */
class MetadataStreamPacketInfo final
{
public:
    explicit MetadataStreamPacketInfo(const ir::ByteOrder byteOrder, const unsigned int major,
                                      const unsigned int minor,
                                      const bt2_common::Uuid& uuid) noexcept :
        _mByteOrder {byteOrder},
        _mMajor {major}, _mMinor {minor}, _mUuid {uuid}
    {
    }

    bool operator==(const MetadataStreamPacketInfo& other) const noexcept
    {
        return _mByteOrder == other._mByteOrder && _mMajor == other._mMajor &&
               _mMinor == other._mMinor && _mUuid == other._mUuid;
    }

    bool operator!=(const MetadataStreamPacketInfo& other) const noexcept
    {
        return !(*this == other);
    }

    ir::ByteOrder byteOrder() const noexcept
    {
        return _mByteOrder;
    }
    unsigned int majorVersion() const noexcept
    {
        return _mMajor;
    }

    unsigned int minorVersion() const noexcept
    {
        return _mMinor;
    }

    const bt2_common::Uuid& uuid() const noexcept
    {
        return _mUuid;
    }

private:
    ir::ByteOrder _mByteOrder;
    unsigned int _mMajor;
    unsigned int _mMinor;
    bt2_common::Uuid _mUuid;
};

/*
 * A metadata stream decoder offers the decode() method to convert
 * either a plain text metadata stream or multiple packets of a
 * packetized metadata stream to plain text.
 *
 * The first call to decode() determines the permanent mode, based on
 * the data, of the decoder, amongst:
 *
 * Plain text mode:
 *     The next calls to decode() only accept plain text metadata stream
 *     data, throwing `bt2_common::Error` otherwise.
 *
 *     pktInfo() returns `nonstd::nullopt`.
 *
 * Packetized mode:
 *     The next calls to decode() only accept packetized metadata stream
 *     data, throwing `bt2_common::Error` otherwise.
 *
 *     Furthermore, the next calls to decode() validate that each
 *     metadata stream packet has the same UUID, again throwing
 *     `bt2_common::Error` otherwise.
 *
 *     pktInfo() returns a value.
 */
class MetadataStreamDecoder final
{
public:
    explicit MetadataStreamDecoder(const bt2_common::LogCfg& logCfg) noexcept;

    /*
     * Decodes the next metadata stream section `data` of length `len`,
     * throwing `bt2_common::Error` on error.
     *
     * `len.hasExtraBits()` must return false.
     *
     * `len.bytes()` must be greater than or equal to 4.
     */
    std::string decode(const uint8_t *data, bt2_common::DataLen len);

    const nonstd::optional<MetadataStreamPacketInfo>& pktInfo() const noexcept
    {
        return _mPktInfo;
    }

private:
    /*
     * Type of metadata stream.
     */
    enum _MetadataStreamType
    {
        PACKETIZED,
        PLAIN_TEXT,
    };

    /*
     * Container of metadata stream packet header information.
     *
     * This structure is not to be used as a direct memory mapping of
     * such a header.
     */
    struct _PktHeader final
    {
        explicit _PktHeader(std::uint32_t magicParam, const bt2_common::Uuid& uuidParam,
                            std::uint32_t checksumParam, bt2_common::DataLen contentLenParam,
                            bt2_common::DataLen totalLenParam, std::uint8_t compressionSchemeParam,
                            std::uint8_t encryptionSchemeParam, std::uint8_t checksumSchemeParam,
                            std::uint8_t majorVersionParam, std::uint8_t minorVersionParam);

        bool versionIsValid() const noexcept
        {
            return majorVersion == 1 && minorVersion == 8;
        }

        static constexpr auto len = bt2_common::DataLen::fromBits(37 * 8);

        std::uint32_t magic;
        bt2_common::Uuid uuid;
        std::uint32_t checksum;
        bt2_common::DataLen contentLen;
        bt2_common::DataLen totalLen;
        std::uint8_t compressionScheme;
        std::uint8_t encryptionScheme;
        std::uint8_t checksumScheme;
        std::uint8_t majorVersion;
        std::uint8_t minorVersion;
    };

    /*
     * Returns the byte order of the metadata stream `data` of length
     * `len`, or `nonstd::nullopt` if `data` doesn't look like a packet
     * header.
     *
     * `len.hasExtraBits()` must return false.
     */
    nonstd::optional<ir::ByteOrder> _getByteOrder(const uint8_t *data,
                                                  bt2_common::DataLen len) const noexcept;

    /*
     * Reads and returns one metadata stream packet header having the
     * byte order `byteOrder` from `buf` at the offset `curOffset`
     * within some metadata stream section.
     *
     * `buf` must offer at least `_PktHeader::len.bytes()` bytes of
     * data.
     *
     * `curOffset.hasExtraBits()` must return false.
     */
    _PktHeader _readPktHeader(const std::uint8_t *buf, ir::ByteOrder byteOrder,
                              bt2_common::DataLen curOffset) const;

    /*
     * Validates the packet header `header`, throwing
     * `bt2_common::Error` if it's invalid.
     */
    void _validatePktHeader(const _PktHeader& header) const;

    /*
     * Returns the plain text data from the packetized metadata
     * stream `data` of length `len`.
     *
     * `len.hasExtraBits()` must return false.
     */
    std::string _textFromPacketizedMetadata(const uint8_t *data, bt2_common::DataLen len);

    /*
     * Sets the current metadata stream type from `data` and `len`
     * if not already done.
     *
     * `len.hasExtraBits()` must return false.
     */
    void _maybeSetMetadataStreamType(const uint8_t *data, bt2_common::DataLen len);

    bt2_common::LogCfg _mLogCfg;
    nonstd::optional<MetadataStreamPacketInfo> _mPktInfo;
    std::size_t _mPktIdx = 0;
    nonstd::optional<_MetadataStreamType> _mStreamType;
};

} /* namespace src */
} /* namespace ctf */

#endif /* _CTF_SRC_METADATA_TSDL_METADATA_STREAM_DECODER_HPP */
