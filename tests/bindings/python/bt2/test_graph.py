from bt2 import values
import collections
import unittest
import copy
import bt2

class _MyIter(bt2._UserNotificationIterator):
    def __init__(self):
        self._build_meta()
        self._at = 0

    def _build_meta(self):
        self._trace = bt2.Trace()
        self._sc = self._trace.create_stream_class()
        self._ec = self._sc.create_event_class()
        self._ec.name = 'salut'
        self._my_int_ft = bt2.SignedIntegerFieldType(32)
        payload_ft = bt2.StructureFieldType()
        payload_ft += collections.OrderedDict([
            ('my_int', self._my_int_ft),
        ])
        self._ec.payload_field_type = payload_ft
        self._stream = self._sc()
        self._packet = self._stream.create_packet()

    def _create_event(self, value):
        ev = self._ec()
        ev.payload_field['my_int'] = value
        ev.packet = self._packet
        return ev



class GraphTestCase(unittest.TestCase):
    def setUp(self):
        self._graph = bt2.Graph()

    def tearDown(self):
        del self._graph

    def test_create_empty(self):
        graph = bt2.Graph()

    def test_add_component_user_cls(self):
        class MySink(bt2._UserSinkComponent):
            def _consume(self):
                pass

        comp = self._graph.add_component(MySink, 'salut')
        self.assertEqual(comp.name, 'salut')

    def test_add_component_gen_cls(self):
        class MySink(bt2._UserSinkComponent):
            def _consume(self):
                pass

        comp = self._graph.add_component(MySink, 'salut')
        assert(comp)
        comp2 = self._graph.add_component(comp.component_class, 'salut2')
        self.assertEqual(comp2.name, 'salut2')

    def test_add_component_params(self):
        comp_params = None

        class MySink(bt2._UserSinkComponent):
            def __init__(self, params):
                nonlocal comp_params
                comp_params = params

            def _consume(self):
                pass

        params = {'hello': 23, 'path': '/path/to/stuff'}
        comp = self._graph.add_component(MySink, 'salut', params)
        self.assertEqual(params, comp_params)
        del comp_params

    def test_add_component_invalid_cls_type(self):
        with self.assertRaises(TypeError):
            self._graph.add_component(int, 'salut')

    def test_connect_ports(self):
        class MyIter(bt2._UserNotificationIterator):
            def __next__(self):
                raise bt2.Stop

        class MySource(bt2._UserSourceComponent,
                       notification_iterator_class=MyIter):
            def __init__(self, params):
                self._add_output_port('out')

        class MySink(bt2._UserSinkComponent):
            def __init__(self, params):
                self._add_input_port('in')

            def _consume(self):
                raise bt2.Stop

        src = self._graph.add_component(MySource, 'src')
        sink = self._graph.add_component(MySink, 'sink')
        conn = self._graph.connect_ports(src.output_ports['out'],
                                         sink.input_ports['in'])
        self.assertTrue(src.output_ports['out'].is_connected)
        self.assertTrue(sink.input_ports['in'].is_connected)
        self.assertEqual(src.output_ports['out'].connection._ptr, conn._ptr)
        self.assertEqual(sink.input_ports['in'].connection._ptr, conn._ptr)

    def test_connect_ports_invalid_direction(self):
        class MyIter(bt2._UserNotificationIterator):
            def __next__(self):
                raise bt2.Stop

        class MySource(bt2._UserSourceComponent,
                       notification_iterator_class=MyIter):
            def __init__(self, params):
                self._add_output_port('out')

        class MySink(bt2._UserSinkComponent):
            def __init__(self, params):
                self._add_input_port('in')

            def _consume(self):
                raise bt2.Stop

        src = self._graph.add_component(MySource, 'src')
        sink = self._graph.add_component(MySink, 'sink')

        with self.assertRaises(TypeError):
            conn = self._graph.connect_ports(sink.input_ports['in'],
                                             src.output_ports['out'])

    def test_connect_ports_refused(self):
        class MyIter(bt2._UserNotificationIterator):
            def __next__(self):
                raise bt2.Stop

        class MySource(bt2._UserSourceComponent,
                       notification_iterator_class=MyIter):
            def __init__(self, params):
                self._add_output_port('out')

        class MySink(bt2._UserSinkComponent):
            def __init__(self, params):
                self._add_input_port('in')

            def _consume(self):
                raise bt2.Stop

            def _accept_port_connection(self, port, other_port):
                return False

        src = self._graph.add_component(MySource, 'src')
        sink = self._graph.add_component(MySink, 'sink')

        with self.assertRaises(bt2.PortConnectionRefused):
            conn = self._graph.connect_ports(src.output_ports['out'],
                                             sink.input_ports['in'])

    def test_connect_ports_canceled(self):
        class MyIter(bt2._UserNotificationIterator):
            def __next__(self):
                raise bt2.Stop

        class MySource(bt2._UserSourceComponent,
                       notification_iterator_class=MyIter):
            def __init__(self, params):
                self._add_output_port('out')

        class MySink(bt2._UserSinkComponent):
            def __init__(self, params):
                self._add_input_port('in')

            def _consume(self):
                raise bt2.Stop

        src = self._graph.add_component(MySource, 'src')
        sink = self._graph.add_component(MySink, 'sink')
        self._graph.cancel()

        with self.assertRaises(bt2.GraphCanceled):
            conn = self._graph.connect_ports(src.output_ports['out'],
                                             sink.input_ports['in'])


    def test_cancel(self):
        self.assertFalse(self._graph.is_canceled)
        self._graph.cancel()
        self.assertTrue(self._graph.is_canceled)

    def test_run(self):
        class MyIter(_MyIter):
            def __next__(self):
                if self._at == 9:
                    raise bt2.Stop

                if self._at == 0:
                    notif = self._create_stream_beginning_notification(self._stream)
                elif self._at == 1:
                    notif = self._create_packet_beginning_notification(self._packet)
                elif self._at == 7:
                    notif = self._create_packet_end_notification(self._packet)
                elif self._at == 8:
                    notif = self._create_stream_end_notification(self._stream)
                else:
                    notif = self._create_event_notification(self._ec, self._packet)

                self._at += 1
                return notif

        class MySource(bt2._UserSourceComponent,
                       notification_iterator_class=MyIter):
            def __init__(self, params):
                self._add_output_port('out')

        class MySink(bt2._UserSinkComponent):
            def __init__(self, params):
                self._add_input_port('in')
                self._at = 0

            def _consume(comp_self):
                notif = next(comp_self._notif_iter)

                if comp_self._at == 0:
                    self.assertIsInstance(notif, bt2.notification._StreamBeginningNotification)
                elif comp_self._at == 1:
                    self.assertIsInstance(notif, bt2.notification._PacketBeginningNotification)
                elif comp_self._at >= 2 and comp_self._at <= 6:
                    self.assertIsInstance(notif, bt2.notification._EventNotification)
                    self.assertEqual(notif.event.event_class.name, 'salut')
                elif comp_self._at == 7:
                    self.assertIsInstance(notif, bt2.notification._PacketEndNotification)
                elif comp_self._at == 8:
                    self.assertIsInstance(notif, bt2.notification._StreamEndNotification)

                comp_self._at += 1

            def _port_connected(self, port, other_port):
                self._notif_iter = port.connection.create_notification_iterator()

        src = self._graph.add_component(MySource, 'src')
        sink = self._graph.add_component(MySink, 'sink')
        conn = self._graph.connect_ports(src.output_ports['out'],
                                         sink.input_ports['in'])
        self._graph.run()

    def test_run_again(self):
        class MyIter(_MyIter):
            def __next__(self):
                if self._at == 3:
                    raise bt2.TryAgain

                if self._at == 0:
                    notif = self._create_stream_beginning_notification(self._stream)
                elif self._at == 1:
                    notif = self._create_packet_beginning_notification(self._packet)
                elif self._at == 2:
                    notif = self._create_event_notification(self._ec, self._packet)

                self._at += 1
                return notif

        class MySource(bt2._UserSourceComponent,
                       notification_iterator_class=MyIter):
            def __init__(self, params):
                self._add_output_port('out')

        class MySink(bt2._UserSinkComponent):
            def __init__(self, params):
                self._add_input_port('in')
                self._at = 0

            def _consume(comp_self):
                notif = next(comp_self._notif_iter)
                if comp_self._at == 0:
                    self.assertIsInstance(notif, bt2.notification._StreamBeginningNotification)
                elif comp_self._at == 1:
                    self.assertIsInstance(notif, bt2.notification._PacketBeginningNotification)
                elif comp_self._at == 2:
                    self.assertIsInstance(notif, bt2.notification._EventNotification)
                    raise bt2.TryAgain
                else:
                    pass

                comp_self._at += 1

            def _port_connected(self, port, other_port):
                self._notif_iter = port.connection.create_notification_iterator()

        src = self._graph.add_component(MySource, 'src')
        sink = self._graph.add_component(MySink, 'sink')
        conn = self._graph.connect_ports(src.output_ports['out'],
                                         sink.input_ports['in'])

        with self.assertRaises(bt2.TryAgain):
            self._graph.run()

    def test_run_error(self):
        class MyIter(_MyIter):
            def __next__(self):
                if self._at == 4:
                    raise bt2.TryAgain

                if self._at == 0:
                    notif = self._create_stream_beginning_notification(self._stream)
                elif self._at == 1:
                    notif = self._create_packet_beginning_notification(self._packet)
                elif self._at == 2:
                    notif = self._create_event_notification(self._ec, self._packet)
                self._at += 1
                return notif

        class MySource(bt2._UserSourceComponent,
                       notification_iterator_class=MyIter):
            def __init__(self, params):
                self._add_output_port('out')

        class MySink(bt2._UserSinkComponent):
            def __init__(self, params):
                self._add_input_port('in')
                self._at = 0

            def _consume(comp_self):
                notif = next(comp_self._notif_iter)
                if comp_self._at == 0:
                    self.assertIsInstance(notif, bt2.notification._StreamBeginningNotification)
                elif comp_self._at == 1:
                    self.assertIsInstance(notif, bt2.nofitication._PacketBeginningNotification)
                elif comp_self._at == 2:
                    self.assertIsInstance(notif, bt2.notification._EventNotification)
                elif comp_self._at == 3:
                    raise RuntimeError('error!')

                comp_self._at += 1

            def _port_connected(self, port, other_port):
                self._notif_iter = port.connection.create_notification_iterator()

        src = self._graph.add_component(MySource, 'src')
        sink = self._graph.add_component(MySink, 'sink')
        conn = self._graph.connect_ports(src.output_ports['out'],
                                         sink.input_ports['in'])

        with self.assertRaises(bt2.Error):
            self._graph.run()

    def test_listeners(self):
        class MyIter(bt2._UserNotificationIterator):
            def __next__(self):
                raise bt2.Stop

        class MySource(bt2._UserSourceComponent,
                       notification_iterator_class=MyIter):
            def __init__(self, params):
                self._add_output_port('out')
                self._add_output_port('zero')

            def _port_connected(self, port, other_port):
                self._output_ports['zero'].remove_from_component()

        class MySink(bt2._UserSinkComponent):
            def __init__(self, params):
                self._add_input_port('in')

            def _consume(self):
                raise bt2.Stop

            def _port_connected(self, port, other_port):
                self._add_input_port('taste')

            def _port_disconnected(self, port):
                port.remove_from_component()

        def port_added_listener(port):
            nonlocal calls
            calls.append((port_added_listener, port))

        def port_removed_listener(port):
            nonlocal calls
            calls.append((port_removed_listener, port))

        def ports_connected_listener(upstream_port, downstream_port):
            nonlocal calls
            calls.append((ports_connected_listener, upstream_port,
                          downstream_port))

        def ports_disconnected_listener(upstream_comp, downstream_comp,
                                        upstream_port, downstream_port):
            nonlocal calls
            calls.append((ports_disconnected_listener, upstream_comp,
                          downstream_comp, upstream_port, downstream_port))

        calls = []
        self._graph.add_listener(bt2.GraphListenerType.PORT_ADDED,
                                 port_added_listener)
        self._graph.add_listener(bt2.GraphListenerType.PORT_REMOVED,
                                 port_removed_listener)
        self._graph.add_listener(bt2.GraphListenerType.PORTS_CONNECTED,
                                 ports_connected_listener)
        self._graph.add_listener(bt2.GraphListenerType.PORTS_DISCONNECTED,
                                 ports_disconnected_listener)
        src = self._graph.add_component(MySource, 'src')
        sink = self._graph.add_component(MySink, 'sink')
        self._graph.connect_ports(src.output_ports['out'],
                                  sink.input_ports['in'])
        sink.input_ports['in'].disconnect()
        self.assertIs(calls[0][0], port_added_listener)
        self.assertEqual(calls[0][1].name, 'out')
        self.assertIs(calls[1][0], port_added_listener)
        self.assertEqual(calls[1][1].name, 'zero')
        self.assertIs(calls[2][0], port_added_listener)
        self.assertEqual(calls[2][1].name, 'in')
        self.assertIs(calls[3][0], port_removed_listener)
        self.assertEqual(calls[3][1].name, 'zero')
        self.assertIs(calls[4][0], port_added_listener)
        self.assertEqual(calls[4][1].name, 'taste')
        self.assertIs(calls[5][0], ports_connected_listener)
        self.assertEqual(calls[5][1].name, 'out')
        self.assertEqual(calls[5][2].name, 'in')
        self.assertIs(calls[6][0], port_removed_listener)
        self.assertEqual(calls[6][1].name, 'in')
        self.assertIs(calls[7][0], ports_disconnected_listener)
        self.assertEqual(calls[7][1].name, 'src')
        self.assertEqual(calls[7][2].name, 'sink')
        self.assertEqual(calls[7][3].name, 'out')
