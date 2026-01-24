# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import bt2
import pytest


def test_get_greatest_operative_mip_version():
    class Source1(
        bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
    ):
        @classmethod
        def _user_get_supported_mip_versions(cls, params, obj, log_level):
            return [0, 1]

    class Source2(
        bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
    ):
        @classmethod
        def _user_get_supported_mip_versions(cls, params, obj, log_level):
            return [0, 2]

    class Source3(
        bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
    ):
        pass

    version = bt2.get_greatest_operative_mip_version(
        [
            bt2.ComponentDescriptor(Source1),
            bt2.ComponentDescriptor(Source2),
            bt2.ComponentDescriptor(Source3),
        ]
    )

    assert version == 0


def test_get_greatest_operative_mip_version_no_match():
    class Source1(
        bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
    ):
        @classmethod
        def _user_get_supported_mip_versions(cls, params, obj, log_level):
            return [0]

    class Source2(
        bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
    ):
        @classmethod
        def _user_get_supported_mip_versions(cls, params, obj, log_level):
            return [1]

    version = bt2.get_greatest_operative_mip_version(
        [
            bt2.ComponentDescriptor(Source1),
            bt2.ComponentDescriptor(Source2),
        ]
    )

    assert version is None


def test_get_greatest_operative_mip_version_empty_descriptors():
    with pytest.raises(ValueError):
        bt2.get_greatest_operative_mip_version([])


def test_get_greatest_operative_mip_version_wrong_descriptor_type():
    class Source1(
        bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
    ):
        @classmethod
        def _user_get_supported_mip_versions(cls, params, obj, log_level):
            return [0, 1]

    with pytest.raises(TypeError):
        bt2.get_greatest_operative_mip_version(
            [bt2.ComponentDescriptor(Source1), object()]
        )


def test_get_greatest_operative_mip_version_wrong_log_level_type():
    class Source1(
        bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
    ):
        pass

    with pytest.raises(TypeError):
        bt2.get_greatest_operative_mip_version(
            [bt2.ComponentDescriptor(Source1)], "lel"
        )


def test_get_maximal_mip_version():
    assert bt2.get_maximal_mip_version() == 1
