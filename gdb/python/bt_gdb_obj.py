# Converts a GDB object (referring to a Babeltrace object) and converts
# it to a bt-analysis model object.
#
# The MIT License (MIT)
#
# Copyright (c) 2016 Philippe Proulx <eepp.ca>
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

from collections import OrderedDict
from btanalysis import model, info
import gdb


def _get_byte_order_string(bo_gdb_obj):
    if int(bo_gdb_obj) == 1234:
        return 'BIG_ENDIAN'
    elif int(bo_gdb_obj) == 4321:
        return 'LITTLE_ENDIAN'
    else:
        # try public API values
        bo_type = gdb.lookup_type('enum bt_ctf_byte_order')

        try:
            bo_enum = bo_gdb_obj.cast(bo_type)
            return str(bo_enum)
        except Exception as e:
            return str(bo_gdb_obj)


def _get_encoding_string(encoding_gdb_obj):
        encoding_type = gdb.lookup_type('enum ctf_string_encoding')

        try:
            encoding_enum = encoding_gdb_obj.cast(encoding_type)
            return str(encoding_enum)
        except Exception as e:
            return str(encoding_gdb_obj)


def _cast_to_cstring(gdb_obj):
    return gdb_obj.cast(gdb.lookup_type('char').pointer())


def _uuid_to_string(uuid_obj):
    import uuid

    char_ptr_type = gdb.lookup_type('unsigned char').pointer()
    char_ptr = uuid_obj.cast(char_ptr_type)
    uuid_values = []

    for i in range(16):
        uuid_values.append(int(char_ptr[i]))

    return uuid.UUID(bytes=bytes(uuid_values))


def _get_is_frozen(gdb_obj):
    return bool(gdb_obj['frozen'])


def _gstring_to_string(gdb_obj):
    if int(gdb_obj) == 0:
        return

    string = gdb_obj['str']

    return str(_cast_to_cstring(string).string())


def _garrayptr_foreach(gdb_obj, gdb_type, override_count=None):
    count = int(gdb_obj['len'])
    pdata = gdb_obj['pdata']

    if override_count is not None:
        count = override_count

    for i in range(count):
        yield pdata[i].cast(gdb_type)


def _get_spec_obj(gdb_obj, type_name):
    spec_type = gdb.lookup_type('struct ' + type_name).pointer()

    return gdb_obj.cast(spec_type)


def _create_object(gdb_obj, addrs_infos):
    base = gdb_obj['base']
    addr = model.Addr(int(gdb_obj))
    refs = int(base['ref_count']['count'])

    return model.Object(addr, refs)


def _create_ctf_ir_ft(gdb_obj, addrs_infos, cls=model.CtfIrFieldType):
    parent = _create_object(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_type')
    is_frozen = _get_is_frozen(spec_obj)
    is_valid = bool(spec_obj['valid'])
    type_id = str(spec_obj['declaration']['id'])

    return cls(parent, is_frozen, is_valid, type_id)


def _create_ctf_ir_unknown_ft(gdb_obj, addrs_infos):
    return _create_ctf_ir_ft(gdb_obj, addrs_infos, model.CtfIrUnknownFieldType)


def _create_ctf_ir_int_ft(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_ft(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_type_integer')
    decl = spec_obj['declaration']
    byte_order = _get_byte_order_string(decl['byte_order'])
    user_byte_order = _get_byte_order_string(spec_obj['user_byte_order'])
    size = int(decl['len'])
    align = int(decl['p']['alignment'])
    is_signed = bool(decl['signedness'])
    base = int(decl['base'])
    encoding = _get_encoding_string(decl['encoding'])
    mapped_clock = model_obj_from_gdb_obj(spec_obj['mapped_clock'], addrs_infos)

    return model.CtfIrIntFieldType(parent, size, byte_order, user_byte_order,
                                   align, is_signed, base, encoding,
                                   mapped_clock)

def _create_ctf_ir_float_ft(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_ft(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_type_floating_point')
    decl = spec_obj['declaration']
    byte_order = _get_byte_order_string(spec_obj['mantissa']['byte_order'])
    user_byte_order = _get_byte_order_string(spec_obj['user_byte_order'])
    exp_size = int(spec_obj['exp']['len'])
    mant_size = int(spec_obj['mantissa']['len'] + 1)
    align = int(decl['p']['alignment'])

    return model.CtfIrFloatFieldType(parent, byte_order, user_byte_order,
                                     align, exp_size, mant_size)


def _get_ctf_ir_enum_ft_mapping(gdb_obj):
    # label
    string_quark = gdb_obj['string']
    call = 'g_quark_to_string({})'.format(string_quark)
    label = gdb.parse_and_eval(call)
    label = str(_cast_to_cstring(label).string())

    # range
    start = int(gdb_obj['range_start']['_signed'])
    end = int(gdb_obj['range_end']['_signed'])
    rg = (start, end)

    return label, rg


def _create_ctf_ir_enum_ft(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_ft(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_type_enumeration')
    container_type = model_obj_from_gdb_obj(spec_obj['container'], addrs_infos)
    enum_mapping_type = gdb.lookup_type('struct enumeration_mapping').pointer()
    mappings = OrderedDict()

    for enum_mapping in _garrayptr_foreach(spec_obj['entries'], enum_mapping_type):
        label, rg = _get_ctf_ir_enum_ft_mapping(enum_mapping)
        mappings[label] = rg

    return model.CtfIrEnumFieldType(parent, mappings, container_type)


def _create_ctf_ir_string_ft(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_ft(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_type_string')
    decl = spec_obj['declaration']
    encoding = _get_encoding_string(decl['encoding'])

    return model.CtfIrStringFieldType(parent, encoding)


def _get_ctf_ir_struct_variant_ft_field(spec_obj, addrs_infos):
    # name
    name_quark = spec_obj['name']
    call = 'g_quark_to_string({})'.format(name_quark)
    name = gdb.parse_and_eval(call)
    name = str(_cast_to_cstring(name).string())

    # type
    type = model_obj_from_gdb_obj(spec_obj['type'], addrs_infos)

    return name, type


def _get_ctf_ir_struct_variant_ft_fields(spec_obj, addrs_infos):
    fields_gdb_obj = spec_obj['fields']
    fields = OrderedDict()
    structure_field_type = gdb.lookup_type('struct structure_field').pointer()

    for struct_field in _garrayptr_foreach(fields_gdb_obj, structure_field_type):
        name, type = _get_ctf_ir_struct_variant_ft_field(struct_field, addrs_infos)
        fields[name] = type

    return fields


def _create_ctf_ir_struct_ft(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_ft(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_type_structure')
    decl = spec_obj['declaration']
    min_align = int(decl['p']['alignment'])
    fields = _get_ctf_ir_struct_variant_ft_fields(spec_obj, addrs_infos)

    return model.CtfIrStructFieldType(parent, min_align, fields)


def _get_field_path(gdb_obj):
    if int(gdb_obj) == 0:
        return

    root = str(gdb_obj['root'])
    garray = gdb_obj['path_indexes']
    length = int(garray['len'])
    path = [root]

    for i in range(length):
        expr = '(((int*) (void *) ((GArray *) {})->data) [{}])'.format(garray, i)
        val = gdb.parse_and_eval(expr)
        path.append(int(val))

    return path


def _create_ctf_ir_variant_ft(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_ft(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_type_variant')
    decl = spec_obj['declaration']
    fields = _get_ctf_ir_struct_variant_ft_fields(spec_obj, addrs_infos)

    # tag name
    tag_name = _gstring_to_string(spec_obj['tag_name'])

    # tag field path
    field_path = _get_field_path(spec_obj['tag_path'])

    # tag type
    ft_type = gdb.lookup_type('struct bt_ctf_field_type').pointer()
    tag_type = model_obj_from_gdb_obj(spec_obj['tag'].cast(ft_type), addrs_infos)

    return model.CtfIrVariantFieldType(parent, tag_name, field_path, tag_type, fields)


def _create_ctf_ir_array_ft(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_ft(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_type_array')
    decl = spec_obj['declaration']
    length = int(decl['len'])
    element_type = model_obj_from_gdb_obj(spec_obj['element_type'], addrs_infos)

    return model.CtfIrArrayFieldType(parent, length, element_type)


def _create_ctf_ir_seq_ft(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_ft(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_type_sequence')
    decl = spec_obj['declaration']
    element_type = model_obj_from_gdb_obj(spec_obj['element_type'], addrs_infos)

    # length name
    length_name = _gstring_to_string(spec_obj['length_field_name'])

    # length field path
    field_path = _get_field_path(spec_obj['length_field_path'])

    return model.CtfIrSeqFieldType(parent, length_name, field_path,
                                   element_type)


def _create_ctf_ir_clock(gdb_obj, addrs_infos):
    parent = _create_object(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_clock')

    # name
    name_obj = spec_obj['name']

    if int(name_obj) == 0:
        name = None
    else:
        name = _gstring_to_string(name_obj)

    # description
    descr_obj = spec_obj['description']

    if int(descr_obj) == 0:
        descr = None
    else:
        descr = _gstring_to_string(descr_obj)

    # rest
    freq = int(spec_obj['frequency'])
    precision = int(spec_obj['precision'])
    offset_seconds = int(spec_obj['offset_s'])
    offset_cycles = int(spec_obj['offset'])
    cycles = int(spec_obj['time'])
    uuid = _uuid_to_string(spec_obj['uuid'])
    is_uuid_set = bool(spec_obj['uuid_set'])
    is_absolute = bool(spec_obj['absolute'])
    is_frozen = _get_is_frozen(spec_obj)

    return model.CtfIrClock(parent, is_frozen, name, descr, freq, precision,
                            offset_seconds, offset_cycles, uuid,
                            is_uuid_set, is_absolute, cycles)


def _create_ctf_ir_event_class(gdb_obj, addrs_infos):
    parent = _create_object(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_event_class')
    is_frozen = _get_is_frozen(spec_obj)
    is_valid = bool(spec_obj['valid'])
    stream_class_addr = model.Addr(int(spec_obj['stream_class']))
    attributes = model_obj_from_gdb_obj(spec_obj['attributes'], addrs_infos)

    # ID
    call = 'bt_ctf_event_class_get_id({})'.format(spec_obj)
    id = int(gdb.parse_and_eval(call))

    # name
    call = 'bt_ctf_event_class_get_name({})'.format(spec_obj)
    name = str(gdb.parse_and_eval(call).string())

    # types
    context_type = model_obj_from_gdb_obj(spec_obj['context'], addrs_infos)
    payload_type = model_obj_from_gdb_obj(spec_obj['fields'], addrs_infos)

    return model.CtfIrEventClass(parent, is_frozen, is_valid, id, name,
                                 attributes, stream_class_addr, context_type,
                                 payload_type)


def _create_ctf_ir_stream_class(gdb_obj, addrs_infos):
    parent = _create_object(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_stream_class')
    is_frozen = _get_is_frozen(spec_obj)
    is_valid = bool(spec_obj['valid'])
    name = _gstring_to_string(spec_obj['name'])
    id = int(spec_obj['id'])
    is_id_set = bool(spec_obj['id_set'])
    next_event_id = int(spec_obj['next_event_id'])
    next_stream_id = int(spec_obj['next_stream_id'])
    packet_context_type = model_obj_from_gdb_obj(spec_obj['packet_context_type'], addrs_infos)
    event_header_type = model_obj_from_gdb_obj(spec_obj['event_header_type'], addrs_infos)
    event_context_type = model_obj_from_gdb_obj(spec_obj['event_context_type'], addrs_infos)
    clock = model_obj_from_gdb_obj(spec_obj['clock'], addrs_infos)
    trace_addr = model.Addr(int(spec_obj['trace']))

    # event classes
    event_classes_garrayptr = spec_obj['event_classes']
    event_class_type = gdb.lookup_type('struct bt_ctf_event_class').pointer()
    event_classes = []

    for event_class in _garrayptr_foreach(event_classes_garrayptr, event_class_type):
        event_classes.append(model_obj_from_gdb_obj(event_class, addrs_infos))

    return model.CtfIrStreamClass(parent, is_frozen, is_valid, id, is_id_set,
                                  name, next_event_id, next_stream_id,
                                  packet_context_type, event_header_type,
                                  event_context_type, clock, trace_addr,
                                  event_classes)


def _create_ctf_ir_trace(gdb_obj, addrs_infos):
    parent = _create_object(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_trace')
    is_frozen = _get_is_frozen(spec_obj)
    is_valid = bool(spec_obj['valid'])
    uuid = _uuid_to_string(spec_obj['uuid'])
    byte_order = _get_byte_order_string(spec_obj['byte_order'])
    next_stream_id = int(spec_obj['next_stream_id'])
    packet_header_type = model_obj_from_gdb_obj(spec_obj['packet_header_type'],
                                                addrs_infos)
    environment = model_obj_from_gdb_obj(spec_obj['environment'], addrs_infos)

    # clocks
    clock_type = gdb.lookup_type('struct bt_ctf_clock').pointer()
    clocks = []

    for clock in _garrayptr_foreach(spec_obj['clocks'], clock_type):
        clocks.append(model_obj_from_gdb_obj(clock, addrs_infos))

    # stream classes
    stream_class_type = gdb.lookup_type('struct bt_ctf_stream_class').pointer()
    stream_classes = []

    for stream_class in _garrayptr_foreach(spec_obj['stream_classes'], stream_class_type):
        stream_classes.append(model_obj_from_gdb_obj(stream_class, addrs_infos))

    return model.CtfIrTrace(parent, is_frozen, is_valid, uuid, byte_order,
                            next_stream_id, environment, packet_header_type,
                            clocks, stream_classes)


def _create_ctf_ir_field(gdb_obj, addrs_infos, cls=model.CtfIrField):
    parent = _create_object(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field')
    field_type = model_obj_from_gdb_obj(spec_obj['type'], addrs_infos)
    is_payload_set = bool(spec_obj['payload_set'])

    return cls(parent, is_payload_set, field_type)


def _create_ctf_ir_unknown_ft(gdb_obj, addrs_infos):
    return _create_ctf_ir_field(gdb_obj, addrs_infos, model.CtfIrUnknownField)


def _create_ctf_ir_int_field(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_field(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_integer')

    if type(parent) is model.CtfIrIntFieldType:
        if parent.field_type.is_signed:
            value = int(spec_obj['definition']['value']['_signed'])
        else:
            value = int(spec_obj['definition']['value']['_unsigned'])
    else:
        value = int(spec_obj['definition']['value']['_unsigned'])

    return model.CtfIrIntField(parent, value)


def _create_ctf_ir_float_field(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_field(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_floating_point')
    value = float(spec_obj['definition']['value'])

    return model.CtfIrFloatField(parent, value)


def _create_ctf_ir_enum_field(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_field(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_enumeration')
    value_field = model_obj_from_gdb_obj(spec_obj['payload'], addrs_infos)

    return model.CtfIrEnumField(parent, value_field)


def _create_ctf_ir_string_field(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_field(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_string')
    value = _gstring_to_string(spec_obj['payload'])

    return model.CtfIrStringField(parent, value)


def _create_ctf_ir_struct_field(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_field(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_structure')
    bt_field_type = gdb.lookup_type('struct bt_ctf_field').pointer()
    fields = OrderedDict()

    if type(parent.field_type) is model.CtfIrStructFieldType:
        field_names = list(parent.field_type.fields.keys())
    else:
        field_names = None

    for index, field in enumerate(_garrayptr_foreach(spec_obj['fields'], bt_field_type)):
        field_obj = model_obj_from_gdb_obj(field, addrs_infos)
        name = '?'

        if field_names is not None:
            name = field_names[index]

        fields[name] = field_obj

    return model.CtfIrStructField(parent, fields)


def _create_ctf_ir_variant_field(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_field(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_variant')
    tag_field = model_obj_from_gdb_obj(spec_obj['tag'], addrs_infos)
    value_field = model_obj_from_gdb_obj(spec_obj['payload'], addrs_infos)

    return model.CtfIrVariantField(parent, tag_field, value_field)


def _create_ctf_ir_array_field(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_field(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_array')
    bt_field_type = gdb.lookup_type('struct bt_ctf_field').pointer()
    elements = []

    for element in _garrayptr_foreach(spec_obj['elements'], bt_field_type):
        bt_obj = model_obj_from_gdb_obj(element, addrs_infos)
        elements.append(bt_obj)

    return model.CtfIrArrayField(parent, elements)


def _create_ctf_ir_seq_field(gdb_obj, addrs_infos):
    parent = _create_ctf_ir_field(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_field_sequence')
    length_field = model_obj_from_gdb_obj(spec_obj['length'], addrs_infos)
    bt_field_type = gdb.lookup_type('struct bt_ctf_field').pointer()
    elements = []

    if type(length_field) is model.CtfIrIntField:
        if length_field.is_payload_set:
            for element in _garrayptr_foreach(spec_obj['elements'], bt_field_type,
                                              length_field.value):
                bt_obj = model_obj_from_gdb_obj(element, addrs_infos)
                elements.append(bt_obj)

    return model.CtfIrSeqField(parent, length_field, elements)


def _create_ctf_ir_event(gdb_obj, addrs_infos):
    parent = _create_object(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_event')
    stream_addr = model.Addr(int(spec_obj['stream']))
    event_class = model_obj_from_gdb_obj(spec_obj['event_class'], addrs_infos)
    header_field = model_obj_from_gdb_obj(spec_obj['event_header'], addrs_infos)
    context_field = model_obj_from_gdb_obj(spec_obj['context_payload'], addrs_infos)
    payload_field = model_obj_from_gdb_obj(spec_obj['fields_payload'], addrs_infos)

    return model.CtfIrEvent(parent, stream_addr, event_class, header_field,
                            context_field, payload_field)


def _create_ctf_ir_stream(gdb_obj, addrs_infos):
    parent = _create_object(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_stream')
    trace_addr = model.Addr(int(spec_obj['trace']))
    id = int(spec_obj['id'])
    fd = int(spec_obj['pos']['fd'])
    flushed_packet_count = int(spec_obj['flushed_packet_count'])
    bt_field_type = gdb.lookup_type('struct bt_ctf_field').pointer()
    event_type = gdb.lookup_type('struct bt_ctf_event').pointer()
    event_context_fields = []

    for field in _garrayptr_foreach(spec_obj['event_contexts'], bt_field_type):
        context_obj = model_obj_from_gdb_obj(field, addrs_infos)
        event_context_fields.append(context_obj)

    events = []

    for event in _garrayptr_foreach(spec_obj['events'], event_type):
        event_obj = model_obj_from_gdb_obj(event, addrs_infos)
        events.append(event_obj)

    stream_class = model_obj_from_gdb_obj(spec_obj['stream_class'], addrs_infos)
    packet_header_field = model_obj_from_gdb_obj(spec_obj['packet_header'], addrs_infos)
    packet_context_field = model_obj_from_gdb_obj(spec_obj['packet_context'], addrs_infos)
    event_header_field = model_obj_from_gdb_obj(spec_obj['event_header'], addrs_infos)
    event_context_field = model_obj_from_gdb_obj(spec_obj['event_context'], addrs_infos)

    return model.CtfIrStream(parent, trace_addr, id, fd, flushed_packet_count,
                             stream_class, events, event_context_fields,
                             packet_header_field, packet_context_field,
                             event_header_field, event_context_field)


def _create_ctf_ir_writer(gdb_obj, addrs_infos):
    parent = _create_object(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_ctf_writer')
    is_frozen = _get_is_frozen(spec_obj)
    trace = model_obj_from_gdb_obj(spec_obj['trace'], addrs_infos)
    path = _gstring_to_string(spec_obj['path'])
    trace_dir_fd = int(spec_obj['trace_dir_fd'])
    metadata_fd = int(spec_obj['metadata_fd'])

    return model.CtfIrWriter(parent, is_frozen, trace_dir_fd, metadata_fd,
                             path, trace)


def _create_value(gdb_obj, addrs_infos, cls=model.Value):
    parent = _create_object(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_value')
    is_frozen = bool(spec_obj['is_frozen'])
    type = str(spec_obj['type'])

    return cls(parent, is_frozen, type)


def _create_unknown_value(gdb_obj, addrs_infos):
    return _create_value(gdb_obj, addrs_infos, model.UnknownValue)


def _create_null_value(gdb_obj, addrs_infos):
    return _create_value(gdb_obj, addrs_infos, model.NullValue)


def _create_bool_value(gdb_obj, addrs_infos):
    parent = _create_value(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_value_bool')
    value = bool(spec_obj['value'])

    return model.BoolValue(parent, value)


def _create_integer_value(gdb_obj, addrs_infos):
    parent = _create_value(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_value_integer')
    value = int(spec_obj['value'])

    return model.IntValue(parent, value)


def _create_float_value(gdb_obj, addrs_infos):
    parent = _create_value(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_value_float')
    value = float(spec_obj['value'])

    return model.FloatValue(parent, value)


def _create_string_value(gdb_obj, addrs_infos):
    parent = _create_value(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_value_string')
    value = _gstring_to_string(spec_obj['gstr'])

    return model.StringValue(parent, value)


def _create_array_value(gdb_obj, addrs_infos):
    parent = _create_value(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_value_array')
    bt_value_type = gdb.lookup_type('struct bt_value').pointer()
    values = []

    for value in _garrayptr_foreach(spec_obj['garray'], bt_value_type):
        value_obj = model_obj_from_gdb_obj(value, addrs_infos)
        values.append(value_obj)

    return model.ArrayValue(parent, values)


def _create_map_value(gdb_obj, addrs_infos):
    parent = _create_value(gdb_obj, addrs_infos)
    spec_obj = _get_spec_obj(gdb_obj, 'bt_value_map')
    ght = spec_obj['ght']
    bt_value_type = gdb.lookup_type('struct bt_value').pointer().pointer()
    ghashtableiter_type = gdb.lookup_type('GHashTableIter').pointer()
    values = OrderedDict()
    iterator = gdb.parse_and_eval('malloc(sizeof(GHashTableIter))')
    iterator = iterator.cast(ghashtableiter_type)
    gdb.parse_and_eval('g_hash_table_iter_init({}, {})'.format(iterator, ght))
    key = gdb.parse_and_eval('malloc(sizeof(gpointer))')
    value = gdb.parse_and_eval('malloc(sizeof(gpointer))')
    ulong_ptr_type = gdb.lookup_type('unsigned long').pointer()

    while True:
        call = 'g_hash_table_iter_next({}, {}, {})'.format(iterator, key, value)
        ret = gdb.parse_and_eval(call)

        if not int(ret):
            break

        key_quark = key.cast(ulong_ptr_type).dereference()
        key_str = gdb.parse_and_eval('g_quark_to_string({})'.format(int(key_quark)))
        key_str = str(_cast_to_cstring(key_str).string())
        bt_value = value.cast(bt_value_type).dereference()
        value_obj = model_obj_from_gdb_obj(bt_value, addrs_infos)
        values[key_str] = value_obj

    free_fmt = 'free({})'
    gdb.parse_and_eval(free_fmt.format(iterator))
    gdb.parse_and_eval(free_fmt.format(key))
    gdb.parse_and_eval(free_fmt.format(value))

    return model.MapValue(parent, values)


_FT_TYPEID_TO_CREATE_FT_FUNC = {
    'CTF_TYPE_INTEGER': _create_ctf_ir_int_ft,
    'CTF_TYPE_FLOAT': _create_ctf_ir_float_ft,
    'CTF_TYPE_ENUM': _create_ctf_ir_enum_ft,
    'CTF_TYPE_STRING': _create_ctf_ir_string_ft,
    'CTF_TYPE_STRUCT': _create_ctf_ir_struct_ft,
    'CTF_TYPE_ARRAY': _create_ctf_ir_array_ft,
    'CTF_TYPE_SEQUENCE': _create_ctf_ir_seq_ft,
    'CTF_TYPE_VARIANT': _create_ctf_ir_variant_ft,
}


_FT_TYPEID_TO_CREATE_FIELD_FUNC = {
    'CTF_TYPE_INTEGER': _create_ctf_ir_int_field,
    'CTF_TYPE_FLOAT': _create_ctf_ir_float_field,
    'CTF_TYPE_ENUM': _create_ctf_ir_enum_field,
    'CTF_TYPE_STRING': _create_ctf_ir_string_field,
    'CTF_TYPE_STRUCT': _create_ctf_ir_struct_field,
    'CTF_TYPE_ARRAY': _create_ctf_ir_array_field,
    'CTF_TYPE_SEQUENCE': _create_ctf_ir_seq_field,
    'CTF_TYPE_VARIANT': _create_ctf_ir_variant_field,
}


_VALUE_TYPE_TO_CREATE_VALUE_FUNC = {
    'BT_VALUE_TYPE_NULL': _create_null_value,
    'BT_VALUE_TYPE_BOOL': _create_bool_value,
    'BT_VALUE_TYPE_INTEGER': _create_integer_value,
    'BT_VALUE_TYPE_FLOAT': _create_float_value,
    'BT_VALUE_TYPE_STRING': _create_string_value,
    'BT_VALUE_TYPE_ARRAY': _create_array_value,
    'BT_VALUE_TYPE_MAP': _create_map_value,
}


_TARGET_TO_CREATE_FUNC = {
    'struct bt_ctf_clock': _create_ctf_ir_clock,
    'struct bt_ctf_event_class': _create_ctf_ir_event_class,
    'struct bt_ctf_stream_class': _create_ctf_ir_stream_class,
    'struct bt_ctf_trace': _create_ctf_ir_trace,
    'struct bt_ctf_event': _create_ctf_ir_event,
    'struct bt_ctf_stream': _create_ctf_ir_stream,
    'struct bt_ctf_writer': _create_ctf_ir_writer,
}


def model_obj_from_gdb_obj(gdb_obj, addrs_infos):
    addr = int(gdb_obj)

    if addr in addrs_infos:
        return addrs_infos[addr].object

    if addr == 0:
        return model.NullPointer()

    try:
        target = str(gdb_obj.type.target())
    except:
        return model.UnknownPointer(model.Addr(addr))

    if target == 'struct bt_ctf_field_type':
        ft_obj = _create_ctf_ir_ft(gdb_obj, addrs_infos)

        if ft_obj.type_id in _FT_TYPEID_TO_CREATE_FT_FUNC:
            obj = _FT_TYPEID_TO_CREATE_FT_FUNC[ft_obj.type_id](gdb_obj, addrs_infos)
        else:
            obj = _create_ctf_ir_unknown_ft(ft_obj, addrs_infos)
    elif target == 'struct bt_ctf_field':
        field_obj = _create_ctf_ir_field(gdb_obj, addrs_infos)
        type_id = field_obj.field_type.type_id

        if type_id in _FT_TYPEID_TO_CREATE_FIELD_FUNC:
            obj = _FT_TYPEID_TO_CREATE_FIELD_FUNC[type_id](gdb_obj, addrs_infos)
        else:
            obj = _create_ctf_ir_unknown_field(field_obj, addrs_infos)
    elif target == 'struct bt_value':
        value_obj = _create_value(gdb_obj, addrs_infos)

        if value_obj.type in _VALUE_TYPE_TO_CREATE_VALUE_FUNC:
            obj = _VALUE_TYPE_TO_CREATE_VALUE_FUNC[value_obj.type](gdb_obj, addrs_infos)
        else:
            obj = _create_unknown_value(value_obj, addrs_infos)
    else:
        if target in _TARGET_TO_CREATE_FUNC:
            obj = _TARGET_TO_CREATE_FUNC[target](gdb_obj, addrs_infos)
        else:
            obj = model.UnknownPointer(model.Addr(addr))

    addrs_infos[addr] = info.AddrInfo(obj)

    return obj
