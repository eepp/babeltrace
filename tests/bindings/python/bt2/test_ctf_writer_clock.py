import unittest
import uuid
import copy
import bt2
import bt2.native_bt
import bt2.ctfwriter


class CtfWriterClockTestCase(unittest.TestCase):
    def setUp(self):
        self._clock = bt2.ctfwriter.CtfWriterClock('salut')

    def tearDown(self):
        del self._clock

    def test_create_default(self):
        self.assertEqual(self._clock.name, 'salut')

    def test_create_invalid_no_name(self):
        with self.assertRaises(TypeError):
            bt2.ctfwriter.CtfWriterClock()

    def test_create_full(self):
        my_uuid = uuid.uuid1()
        cc = bt2.ctfwriter.CtfWriterClock(name='name', description='some description',
                                frequency=1001, precision=176,
                                offset=bt2.ClockClassOffset(45, 3003),
                                is_absolute=True, uuid=my_uuid)
        self.assertEqual(cc.name, 'name')
        self.assertEqual(cc.description, 'some description')
        self.assertEqual(cc.frequency, 1001)
        self.assertEqual(cc.precision, 176)
        self.assertEqual(cc.offset, bt2.ClockClassOffset(45, 3003))
        self.assertEqual(cc.is_absolute, True)
        self.assertEqual(cc.uuid, copy.deepcopy(my_uuid))

    def test_assign_description(self):
        self._clock.description = 'hi people'
        self.assertEqual(self._clock.description, 'hi people')

    def test_assign_invalid_description(self):
        with self.assertRaises(TypeError):
            self._clock.description = 23

    def test_assign_frequency(self):
        self._clock.frequency = 987654321
        self.assertEqual(self._clock.frequency, 987654321)

    def test_assign_invalid_frequency(self):
        with self.assertRaises(TypeError):
            self._clock.frequency = 'lel'

    def test_assign_precision(self):
        self._clock.precision = 12
        self.assertEqual(self._clock.precision, 12)

    def test_assign_invalid_precision(self):
        with self.assertRaises(TypeError):
            self._clock.precision = 'lel'

    def test_assign_offset(self):
        self._clock.offset = bt2.ClockClassOffset(12, 56)
        self.assertEqual(self._clock.offset, bt2.ClockClassOffset(12, 56))

    def test_assign_invalid_offset(self):
        with self.assertRaises(TypeError):
            self._clock.offset = object()

    def test_assign_absolute(self):
        self._clock.is_absolute = True
        self.assertTrue(self._clock.is_absolute)

    def test_assign_invalid_absolute(self):
        with self.assertRaises(TypeError):
            self._clock.is_absolute = 23

    def test_assign_uuid(self):
        the_uuid = uuid.uuid1()
        self._clock.uuid = the_uuid
        self.assertEqual(self._clock.uuid, the_uuid)

    def test_assign_invalid_uuid(self):
        with self.assertRaises(TypeError):
            self._clock.uuid = object()

    def test_assign_time(self):
        self._clock.time = 41232

    def test_assign_invalid_time(self):
        with self.assertRaises(TypeError):
            self._clock.time = object()
