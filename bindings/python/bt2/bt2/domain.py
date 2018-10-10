# The MIT License (MIT)
#
# Copyright (c) 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import bt2.native_bt as native_bt


class _Domain():
    pass
    # Field type id
    FIELD_TYPE_ID_UNSIGNED_INTEGER = native_bt.FIELD_TYPE_ID_UNSIGNED_INTEGER
    FIELD_TYPE_ID_SIGNED_INTEGER = native_bt.FIELD_TYPE_ID_SIGNED_INTEGER
    FIELD_TYPE_ID_UNSIGNED_ENUMERATION = native_bt.FIELD_TYPE_ID_UNSIGNED_ENUMERATION
    FIELD_TYPE_ID_SIGNED_ENUMERATION	= native_bt.FIELD_TYPE_ID_SIGNED_ENUMERATION
    FIELD_TYPE_ID_REAL = native_bt.FIELD_TYPE_ID_REAL
    FIELD_TYPE_ID_STRING = native_bt.FIELD_TYPE_ID_STRING
    FIELD_TYPE_ID_STRUCTURE = native_bt.FIELD_TYPE_ID_STRUCTURE
    FIELD_TYPE_ID_STATIC_ARRAY = native_bt.FIELD_TYPE_ID_STATIC_ARRAY
    FIELD_TYPE_ID_DYNAMIC_ARRAY = native_bt.FIELD_TYPE_ID_DYNAMIC_ARRAY
    FIELD_TYPE_ID_VARIANT = native_bt.FIELD_TYPE_ID_VARIANT

    # Field id
    FIELD_ID_UNSIGNED_INTEGER = native_bt.FIELD_TYPE_ID_UNSIGNED_INTEGER
    FIELD_ID_SIGNED_INTEGER = native_bt.FIELD_TYPE_ID_SIGNED_INTEGER
    FIELD_ID_UNSIGNED_ENUMERATION = native_bt.FIELD_TYPE_ID_UNSIGNED_ENUMERATION
    FIELD_ID_SIGNED_ENUMERATION	= native_bt.FIELD_TYPE_ID_SIGNED_ENUMERATION
    FIELD_ID_REAL = native_bt.FIELD_TYPE_ID_REAL
    FIELD_ID_STRING = native_bt.FIELD_TYPE_ID_STRING
    FIELD_ID_STRUCTURE = native_bt.FIELD_TYPE_ID_STRUCTURE
    FIELD_ID_STATIC_ARRAY = native_bt.FIELD_TYPE_ID_STATIC_ARRAY
    FIELD_ID_DYNAMIC_ARRAY = native_bt.FIELD_TYPE_ID_DYNAMIC_ARRAY
    FIELD_ID_VARIANT = native_bt.FIELD_TYPE_ID_VARIANT

    # Event

#    # Event Class
#    event_class_create = native_bt.event_class_create
#    event_class_get_stream_class = native_bt.event_class_get_stream_class
#    event_class_get_name = native_bt.event_class_get_name
#    event_class_get_id = native_bt.event_class_get_id
#    event_class_set_id = native_bt.event_class_set_id
#    event_class_get_log_level = native_bt.event_class_get_log_level
#    event_class_set_log_level = native_bt.event_class_set_log_level
#    event_class_get_emf_uri = native_bt.event_class_get_emf_uri
#    event_class_set_emf_uri = native_bt.event_class_set_emf_uri
#    event_class_get_context_field_type = native_bt.event_class_get_context_field_type
#    event_class_set_context_field_type = native_bt.event_class_set_context_field_type
#    event_class_get_payload_field_type = native_bt.event_class_get_payload_field_type
#    event_class_set_payload_field_type = native_bt.event_class_set_payload_field_type
#
#    # Event Class Log Level
#    class EventClassLogLevel:
#        UNKNOWN = native_bt.EVENT_CLASS_LOG_LEVEL_UNKNOWN
#        UNSPECIFIED = native_bt.EVENT_CLASS_LOG_LEVEL_UNSPECIFIED
#        EMERGENCY = native_bt.EVENT_CLASS_LOG_LEVEL_EMERGENCY
#        ALERT = native_bt.EVENT_CLASS_LOG_LEVEL_ALERT
#        CRITICAL = native_bt.EVENT_CLASS_LOG_LEVEL_CRITICAL
#        ERROR = native_bt.EVENT_CLASS_LOG_LEVEL_ERROR
#        WARNING = native_bt.EVENT_CLASS_LOG_LEVEL_WARNING
#        NOTICE = native_bt.EVENT_CLASS_LOG_LEVEL_NOTICE
#        INFO = native_bt.EVENT_CLASS_LOG_LEVEL_INFO
#        DEBUG_SYSTEM = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_SYSTEM
#        DEBUG_PROGRAM = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_PROGRAM
#        DEBUG_PROCESS = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_PROCESS
#        DEBUG_MODULE = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_MODULE
#        DEBUG_UNIT = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_UNIT
#        DEBUG_FUNCTION = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_FUNCTION
#        DEBUG_LINE = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_LINE
#        DEBUG = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG
#
#    class ByteOrder:
#        NATIVE = native_bt.BYTE_ORDER_NATIVE
#        LITTLE_ENDIAN = native_bt.BYTE_ORDER_LITTLE_ENDIAN
#        BIG_ENDIAN = native_bt.BYTE_ORDER_BIG_ENDIAN
#        NETWORK = native_bt.BYTE_ORDER_NETWORK
#
#
#    class Encoding:
#        NONE = native_bt.STRING_ENCODING_NONE
#        UTF8 = native_bt.STRING_ENCODING_UTF8
#        ASCII = native_bt.STRING_ENCODING_ASCII
#
#
#    class Base:
#        BINARY = native_bt.INTEGER_BASE_BINARY
#        OCTAL = native_bt.INTEGER_BASE_OCTAL
#        DECIMAL = native_bt.INTEGER_BASE_DECIMAL
#        HEXADECIMAL = native_bt.INTEGER_BASE_HEXADECIMAL
#
#
#    # Field
#    field_get_type = native_bt.field_get_type
#
#    field_integer_signed_get_value = native_bt.field_integer_signed_get_value
#    field_integer_signed_set_value = native_bt.field_integer_signed_set_value
#    field_integer_unsigned_get_value = native_bt.field_integer_unsigned_get_value
#    field_integer_unsigned_set_value = native_bt.field_integer_unsigned_set_value
#
#    field_floating_point_get_value = native_bt.field_floating_point_get_value
#    field_floating_point_set_value = native_bt.field_floating_point_set_value
#
#    field_enumeration_get_mappings = native_bt.field_enumeration_get_mappings
#
#    field_string_get_value = native_bt.field_string_get_value
#    field_string_set_value = native_bt.field_string_set_value
#    field_string_append = native_bt.field_string_append
#    field_string_append_len = native_bt.field_string_append_len
#
#    field_structure_borrow_field_by_index = native_bt.field_structure_borrow_field_by_index
#
#    field_array_borrow_field = native_bt.field_array_borrow_field
#
#    field_sequence_get_length = native_bt.field_sequence_get_length
#    field_sequence_set_length = native_bt.field_sequence_set_length
#    field_sequence_borrow_field = native_bt.field_sequence_borrow_field
#
#
#    field_variant_get_tag_signed = native_bt.field_variant_get_tag_signed
#    field_variant_get_tag_unsigned = native_bt.field_variant_get_tag_unsigned
#    field_variant_set_tag_signed = native_bt.field_variant_set_tag_signed
#    field_variant_set_tag_unsigned = native_bt.field_variant_set_tag_unsigned
#    field_variant_borrow_current_field = native_bt.field_variant_borrow_current_field
#
#    # Field type
#    field_type_get_type_id = native_bt.field_type_get_type_id
#    field_type_get_alignment = native_bt.field_type_get_alignment
#    field_type_set_alignment = native_bt.field_type_set_alignment
#    field_type_get_byte_order = native_bt.field_type_get_byte_order
#    field_type_set_byte_order = native_bt.field_type_set_byte_order
#    field_type_compare = native_bt.field_type_compare
#    field_type_copy = native_bt.field_type_copy
#
#    field_type_integer_create = native_bt.field_type_integer_create
#    field_type_integer_get_size = native_bt.field_type_integer_get_size
#    field_type_integer_set_size = native_bt.field_type_integer_set_size
#    field_type_integer_is_signed = native_bt.field_type_integer_is_signed
#    field_type_integer_set_is_signed = native_bt.field_type_integer_set_is_signed
#    field_type_integer_get_base = native_bt.field_type_integer_get_base
#    field_type_integer_set_base = native_bt.field_type_integer_set_base
#    field_type_integer_get_encoding = native_bt.field_type_integer_get_encoding
#    field_type_integer_set_encoding = native_bt.field_type_integer_set_encoding
#    field_type_integer_get_mapped_clock_class = native_bt.field_type_integer_get_mapped_clock_class
#    field_type_integer_set_mapped_clock_class = native_bt.field_type_integer_set_mapped_clock_class
#    field_type_floating_point_create = native_bt.field_type_floating_point_create
#    field_type_floating_point_get_exponent_digits = native_bt.field_type_floating_point_get_exponent_digits
#    field_type_floating_point_set_exponent_digits = native_bt.field_type_floating_point_set_exponent_digits
#    field_type_floating_point_get_mantissa_digits = native_bt.field_type_floating_point_get_mantissa_digits
#    field_type_floating_point_set_mantissa_digits = native_bt.field_type_floating_point_set_mantissa_digits
#
#    field_type_enumeration_create = native_bt.field_type_enumeration_create
#    field_type_enumeration_borrow_container_field_type = native_bt.field_type_enumeration_borrow_container_field_type
#    field_type_enumeration_get_container_field_type = native_bt.field_type_enumeration_get_container_field_type
#    field_type_enumeration_get_mapping_count = native_bt.field_type_enumeration_get_mapping_count
#    field_type_enumeration_signed_get_mapping_by_index = native_bt.field_type_enumeration_signed_get_mapping_by_index
#    field_type_enumeration_unsigned_get_mapping_by_index = native_bt.field_type_enumeration_unsigned_get_mapping_by_index
#    field_type_enumeration_signed_add_mapping = native_bt.field_type_enumeration_signed_add_mapping
#    field_type_enumeration_unsigned_add_mapping = native_bt.field_type_enumeration_unsigned_add_mapping
#    field_type_enumeration_find_mappings_by_name = native_bt.field_type_enumeration_find_mappings_by_name
#    field_type_enumeration_signed_find_mappings_by_value = native_bt.field_type_enumeration_signed_find_mappings_by_value
#    field_type_enumeration_unsigned_find_mappings_by_value = native_bt.field_type_enumeration_unsigned_find_mappings_by_value
#
#    field_type_enumeration_mapping_iterator_signed_get = native_bt.field_type_enumeration_mapping_iterator_signed_get
#    field_type_enumeration_mapping_iterator_unsigned_get = native_bt.field_type_enumeration_mapping_iterator_unsigned_get
#    field_type_enumeration_mapping_iterator_next = native_bt.field_type_enumeration_mapping_iterator_next
#
#    field_type_string_create = native_bt.field_type_string_create
#    field_type_string_get_encoding = native_bt.field_type_string_get_encoding
#    field_type_string_set_encoding = native_bt.field_type_string_set_encoding
#
#    field_type_structure_create = native_bt.field_type_structure_create
#    field_type_structure_get_field_count = native_bt.field_type_structure_get_field_count
#
#    field_type_structure_borrow_field_by_index = native_bt.field_type_structure_borrow_field_by_index
#    field_type_structure_get_field_by_index = native_bt.field_type_structure_get_field_by_index
#    field_type_structure_borrow_field_type_by_name = native_bt.field_type_structure_borrow_field_type_by_name
#    field_type_structure_get_field_type_by_name = native_bt.field_type_structure_get_field_type_by_name
#
#    field_type_structure_add_field = native_bt.field_type_structure_add_field
#
#    field_type_array_create = native_bt.field_type_array_create
#    field_type_array_get_element_field_type = native_bt.field_type_array_get_element_field_type
#    field_type_array_get_length = native_bt.field_type_array_get_length
#
#    field_type_sequence_create = native_bt.field_type_sequence_create
#    field_type_sequence_get_element_field_type = native_bt.field_type_sequence_get_element_field_type
#    field_type_sequence_get_length_field_name = native_bt.field_type_sequence_get_length_field_name
#    field_type_sequence_get_length_field_path = native_bt.field_type_sequence_get_length_field_path
#
#    field_type_variant_create = native_bt.field_type_variant_create
#    field_type_variant_get_tag_name = native_bt.field_type_variant_get_tag_name
#    field_type_variant_set_tag_name = native_bt.field_type_variant_set_tag_name
#    field_type_variant_get_tag_field_path = native_bt.field_type_variant_get_tag_field_path
#    field_type_variant_get_field_count = native_bt.field_type_variant_get_field_count
#    field_type_variant_get_field_by_index = native_bt.field_type_variant_get_field_by_index
#    field_type_variant_get_field_type_by_name = native_bt.field_type_variant_get_field_type_by_name
#    field_type_variant_add_field = native_bt.field_type_variant_add_field
#    field_type_variant_borrow_tag_field_type = native_bt.field_type_variant_borrow_tag_field_type
#
#    # Stream
#    stream_create = native_bt.stream_create
#    stream_get_name = native_bt.stream_get_name
#    stream_get_id = native_bt.stream_get_id
#    stream_get_class = native_bt.stream_get_class
#
#    # Stream Class
#    stream_class_create = native_bt.stream_class_create
#    stream_class_get_trace = native_bt.stream_class_get_trace
#    stream_class_get_name = native_bt.stream_class_get_name
#    stream_class_set_name = native_bt.stream_class_set_name
#    stream_class_get_id = native_bt.stream_class_get_id
#    stream_class_set_id = native_bt.stream_class_set_id
#    stream_class_get_packet_context_field_type = native_bt.stream_class_get_packet_context_field_type
#    stream_class_set_packet_context_field_type = native_bt.stream_class_set_packet_context_field_type
#    stream_class_get_event_header_field_type = native_bt.stream_class_get_event_header_field_type
#    stream_class_set_event_header_field_type = native_bt.stream_class_set_event_header_field_type
#    stream_class_get_event_context_field_type = native_bt.stream_class_get_event_context_field_type
#    stream_class_set_event_context_field_type = native_bt.stream_class_set_event_context_field_type
#    stream_class_get_event_class_count = native_bt.stream_class_get_event_class_count
#    stream_class_get_event_class_by_index = native_bt.stream_class_get_event_class_by_index
#    stream_class_get_event_class_by_id = native_bt.stream_class_get_event_class_by_id
#    stream_class_add_event_class = native_bt.stream_class_add_event_class
#
#    # Trace
#    trace_get_name = native_bt.trace_get_name
#    trace_set_name = native_bt.trace_set_name
#    trace_get_native_byte_order = native_bt.trace_get_native_byte_order
#    trace_set_native_byte_order = native_bt.trace_set_native_byte_order
#    trace_get_uuid = native_bt.trace_get_uuid
#    trace_set_uuid = native_bt.trace_set_uuid
#    trace_get_environment_field_count = native_bt.trace_get_environment_field_count
#    trace_get_environment_field_name_by_index = native_bt.trace_get_environment_field_name_by_index
#    trace_get_environment_field_value_by_index = native_bt.trace_get_environment_field_value_by_index
#    trace_get_environment_field_value_by_name = native_bt.trace_get_environment_field_value_by_name
#    trace_set_environment_field = native_bt.trace_set_environment_field
#    trace_get_packet_header_field_type = native_bt.trace_get_packet_header_field_type
#    trace_set_packet_header_field_type = native_bt.trace_set_packet_header_field_type
#    trace_get_clock_class_count = native_bt.trace_get_clock_class_count
#    trace_get_clock_class_by_index = native_bt.trace_get_clock_class_by_index
#    trace_get_clock_class_by_name = native_bt.trace_get_clock_class_by_name
#    trace_add_clock_class = native_bt.trace_add_clock_class
#    trace_get_stream_class_count = native_bt.trace_get_stream_class_count
#    trace_get_stream_class_by_index = native_bt.trace_get_stream_class_by_index
#    trace_get_stream_class_by_id = native_bt.trace_get_stream_class_by_id
#    trace_add_stream_class = native_bt.trace_add_stream_class
#    trace_get_stream_count = native_bt.trace_get_stream_count
#    trace_get_stream_by_index = native_bt.trace_get_stream_by_index

class _DomainProvider:
    _Domain = _Domain
