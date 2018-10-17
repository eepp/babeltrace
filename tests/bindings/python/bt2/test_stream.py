from collections import OrderedDict
from bt2 import values
import unittest
import bt2


class StreamTestCase(unittest.TestCase):
    def setUp(self):
        trace = bt2.Trace()
        self._sc = trace.create_stream_class(automatic_stream_id=False)
        self._stream = self._sc(id=1608)

    def tearDown(self):
        del self._sc
        del self._stream

    def test_attr_stream_class(self):
        self.assertEqual(self._stream.stream_class.addr, self._sc.addr)

    def test_attr_name(self):
        self._stream.name = 'my_stream'
        self.assertEqual(self._stream.name, 'my_stream')

    def test_attr_id(self):
        self.assertEqual(self._stream.id, 1608)

    def test_default_clock_always_known(self):
        pass

    def test_counter_snapshots(self):
        pass

    def test_packet_default_clock_value(self):
        pass
