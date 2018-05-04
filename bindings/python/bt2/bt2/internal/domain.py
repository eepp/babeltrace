from bt2 import utils
from . import event, event_class
class _Domain:
    @classmethod
    def create_field_type_from_ptr(cls, ptr):
        typeid = cls.field_type_get_type_id(ptr)
        return cls._FIELD_TYPE_ID_TO_OBJ[typeid]._create_from_ptr(ptr)

    @classmethod
    def create_field_from_ptr(cls, ptr):
        # recreate the field type wrapper of this field's type (the identity
        # could be different, but the underlying address should be the
        # same)
        field_type_ptr = cls.field_get_type(ptr)
        utils._handle_ptr(field_type_ptr, "cannot get field object's type")
        field_type = cls.create_field_type_from_ptr(field_type_ptr)
        typeid = cls.field_type_get_type_id(field_type._ptr)
        field = cls._FIELD_ID_TO_OBJ[typeid]._create_from_ptr(ptr)
        field._field_type = field_type
        return field

    @classmethod
    def create_event_from_ptr(cls, ptr):
        # recreate the event class wrapper of this event's class (the
        # identity could be different, but the underlying address should be
        # the same)
        event_class_ptr = cls.event_get_class(ptr)
        utils._handle_ptr(event_class_ptr, "cannot get event object's class")
        new_event_class = cls.EventClass._create_from_ptr(event_class_ptr)
        new_event = cls.Event._create_from_ptr(ptr)
        new_event._event_class = new_event_class
        return new_event

    @classmethod
    def create_stream_from_ptr(cls, ptr):
        return cls.Stream._create_from_ptr(ptr)

