from xml.etree.ElementTree import ElementTree
from termcolor import colored
import sys


def err(msg, exit=True):
    print(colored('Error: {}'.format(msg), 'red', attrs=['bold']))

    if exit:
        sys.exit(1)


class AddressEntry:
    def __init__(self, elem, ref_elem):
        self.elem = elem
        self.ref_elems = [ref_elem]


class ReportGenerator:
    def __init__(self, path):
        try:
            self._trace_elem = ElementTree()
            self._trace_elem.parse(path)
        except:
            err('cannot open/parse "{}"'.format(path))

        self._addrs = {}
        self._dup_addrs = []
        self._clocks_count = 0
        self._events_count = 0
        self._streams_count = 0
        self._elem_stack = []
        self._weird_refs_elems = []
        self._gen()

    def _add_addr_entry(self, addr, elem, ref_elem):
        if addr in self._addrs:
            self._addrs[addr].ref_elems.append(ref_elem)
        else:
            self._addrs[addr] = AddressEntry(elem, ref_elem)

    def _fill_addrs(self, elem):
        addr = elem.get('addr')

        if addr is not None:
            found_ref_elem = None

            for ref_elem in reversed(self._elem_stack):
                ref_elem_addr = ref_elem.get('addr')

                if ref_elem_addr is not None:
                    found_ref_elem = ref_elem
                    break

            self._add_addr_entry(addr, elem, found_ref_elem)

        self._elem_stack.append(elem)

        for child_elem in elem:
            self._fill_addrs(child_elem)

        self._elem_stack.pop()

    def _find_dup_addrs(self):
        for addr, entry in self._addrs.items():
            if len(entry.ref_elems) > 1:
                self._dup_addrs.append(addr)

    def _set_clock_counts(self):
        self._clocks_count = len(self._trace_elem.find('clocks'))

    def _set_streams_events_counts(self):
        for stream_elem in self._trace_elem.find('stream-classes'):
            self._streams_count += 1

            for event_elem in stream_elem.find('event-classes'):
                self._events_count += 1

    def _find_weird_refs_elems(self, elem):
        refs = elem.get('refs')

        if refs is not None and int(refs) != 1:
            found = False

            for wr_elem in self._weird_refs_elems:
                if wr_elem.get('addr') == elem.get('addr'):
                    found = True
                    break

            if not found:
                self._weird_refs_elems.append(elem)

        for child_elem in elem:
            self._find_weird_refs_elems(child_elem)

    def _gen(self):
        self._fill_addrs(self._trace_elem.getroot())
        self._find_weird_refs_elems(self._trace_elem.getroot())
        self._find_dup_addrs()
        self._set_clock_counts()
        self._set_streams_events_counts()

    def get_all_addrs(self):
        return self._addrs

    def get_dup_addrs(self):
        return self._dup_addrs

    def get_clocks_count(self):
        return self._clocks_count

    def get_streams_count(self):
        return self._streams_count

    def get_events_count(self):
        return self._events_count

    def get_weird_refs_elems(self):
        return self._weird_refs_elems


def get_report_gen(path):
    return ReportGenerator(path)


def _get_addr_elem_str(elem):
    return '{}@{}'.format(colored(elem.tag, 'cyan'),
                          colored(elem.get('addr'), 'yellow'))


def _get_addr_entry_ref_str(addr, entry):
    fmt = '    {}: {} time{}'
    str = fmt.format(_get_addr_elem_str(entry.elem), len(entry.ref_elems),
                     '' if len(entry.ref_elems) == 1 else 's')

    return str


def print_all_addrs(report_gen):
    all_addrs = report_gen.get_all_addrs()
    print('all objects ({}):'.format(len(all_addrs)))

    for addr, entry in all_addrs.items():
        print(_get_addr_entry_ref_str(addr, entry))


def print_dup_addrs(report_gen):
    all_addrs = report_gen.get_all_addrs()
    dup_addrs = report_gen.get_dup_addrs()
    print('referenced more than once ({}):'.format(len(dup_addrs)))

    if not dup_addrs:
        print('    {}'.format(colored('none', 'green')))
        return

    for addr in dup_addrs:
        entry = all_addrs[addr]
        print(_get_addr_entry_ref_str(addr, entry))

        for ref_elem in entry.ref_elems:
            print('        {}'.format(_get_addr_elem_str(ref_elem)))


def print_counts(report_gen):
    fmt = 'clocks count: {}'
    print(fmt.format(colored(report_gen.get_clocks_count(), attrs=['bold'])))
    fmt = 'events count: {}'
    print(fmt.format(colored(report_gen.get_events_count(), attrs=['bold'])))
    fmt = 'streams count: {}'
    print(fmt.format(colored(report_gen.get_streams_count(), attrs=['bold'])))


def print_weird_refs_elems(report_gen):
    print('objects with a ref count != 1:')
    weird_refs_elems = report_gen.get_weird_refs_elems()

    if not weird_refs_elems:
        print('    {}'.format(colored('none', 'green')))
        return

    for elem in weird_refs_elems:
        print('    {}: {} references'.format(_get_addr_elem_str(elem),
                                             elem.get('refs')))


def print_report(path):
    report_gen = get_report_gen(path)

    print_counts(report_gen)
    print()
    print_dup_addrs(report_gen)
    print()
    print_weird_refs_elems(report_gen)


if __name__ == '__main__':
    print_report(sys.argv[1])
