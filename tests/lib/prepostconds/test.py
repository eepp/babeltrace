# SPDX-License-Identifier: MIT
#
# Copyright (c) 2020 Philippe Proulx <pproulx@efficios.com>

import unittest
import subprocess
import functools
import signal
import os
import os.path
import re
import json


# the `prepostconds-triggers` program's full path
_PREPOSTCONDS_TRIGGERS_PATH = os.path.join(
    os.environ['BT_TESTS_LIB_PREPOSTCONDS_BUILDDIR'], 'prepostconds-triggers'
)


# test methods are added by _create_tests()
class LibPrePostCondsTestCase(unittest.TestCase):
    pass


# a condition trigger descriptor (base)
class _CondTriggerDescriptor:
    def __init__(self, index, name, regex):
        self._index = index
        self._name = name
        self._pattern = re.compile(regex)

    @property
    def index(self):
        return self._index

    @property
    def name(self):
        return self._name

    @property
    def pattern(self):
        return self._pattern


# precondition trigger descriptor
class _PreCondTriggerDescriptor(_CondTriggerDescriptor):
    @property
    def type_str(self):
        return 'pre'


# postcondition trigger descriptor
class _PostCondTriggerDescriptor(_CondTriggerDescriptor):
    @property
    def type_str(self):
        return 'post'


# test method template for `LibPrePostCondsTestCase`
def _test(self, descriptor):
    # Execute:
    #
    #     $ prepostconds-triggers run <index>
    #
    # where `<index>` is the descriptor's index.
    with subprocess.Popen(
        [_PREPOSTCONDS_TRIGGERS_PATH, 'run', str(descriptor.index)],
        stderr=subprocess.PIPE,
        universal_newlines=True,
    ) as proc:
        # wait for termination and get standard output/error data
        timeout = 5

        try:
            # wait for program end and get standard error pipe's contents
            _, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.fail('Process hanged for {} seconds'.format(timeout))
            return

        # assert that program aborted (only available on POSIX)
        if os.name == 'posix':
            self.assertEqual(proc.returncode, -int(signal.SIGABRT))

        # assert that it's the right type of condition
        text = 'Babeltrace 2 library {}condition not satisfied'.format(
            descriptor.type_str
        )
        self.assertIn(text, stderr)

        # assert that the standard error text matches the provided regex
        self.assertRegex(stderr, descriptor.pattern)


# Condition trigger descriptors from the JSON array returned by
#
#     $ prepostconds-triggers list
def _cond_trigger_descriptors_from_json(json_descr_array):
    descriptors = []
    descriptor_names = set()

    for index, json_descr in enumerate(json_descr_array):
        # sanity check: check for duplicate
        name = json_descr['name']

        if name in descriptor_names:
            raise ValueError('Duplicate condition trigger name `{}`'.format(name))

        type_str = json_descr['type']

        if type_str == 'pre':
            cond_type = _PreCondTriggerDescriptor
        elif type_str == 'post':
            cond_type = _PostCondTriggerDescriptor

        descriptors.append(cond_type(index, name, json_descr['regex']))
        descriptor_names.add(name)

    return descriptors


# creates the individual tests of `LibPrePostCondsTestCase`
def _create_tests():
    # Execute `prepostconds list` to get a JSON array of condition
    # trigger descriptors.
    json_descr_array = json.loads(
        subprocess.check_output(
            [_PREPOSTCONDS_TRIGGERS_PATH, 'list'], universal_newlines=True
        )
    )

    # get condition trigger descriptor objects from JSON
    descriptors = _cond_trigger_descriptors_from_json(json_descr_array)

    # create test methods
    for descriptor in descriptors:
        # test method name
        test_meth_name = 'test_{}'.format(
            re.sub(r'[^a-zA-Z0-9_]', '_', descriptor.name)
        )

        # test method
        meth = functools.partialmethod(_test, descriptor)
        setattr(LibPrePostCondsTestCase, test_meth_name, meth)


_create_tests()


if __name__ == '__main__':
    unittest.main()
