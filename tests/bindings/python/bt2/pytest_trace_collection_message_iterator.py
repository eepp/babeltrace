# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2019-2026 EfficiOS Inc.

import os
import datetime

import bt2
import pytest


def test_comp_spec_create_src_from_name():
    spec = bt2.ComponentSpec.from_named_plugin_and_component_class("text", "dmesg")
    assert spec.component_class.name == "dmesg"


def test_comp_spec_create_src_from_plugin(dmesg_comp_cls):
    assert bt2.ComponentSpec(dmesg_comp_cls).component_class.name == "dmesg"


class _SomeSrc(
    bt2._UserSourceComponent, message_iterator_class=bt2._UserMessageIterator
):
    pass


def test_comp_spec_create_src_from_user():
    assert bt2.ComponentSpec(_SomeSrc).component_class.name == "_SomeSrc"


def test_comp_spec_create_flt_from_name():
    spec = bt2.ComponentSpec.from_named_plugin_and_component_class("utils", "muxer")
    assert spec.component_class.name == "muxer"


def test_comp_spec_create_flt_from_object(muxer_comp_cls):
    assert bt2.ComponentSpec(muxer_comp_cls).component_class.name == "muxer"


def test_comp_spec_create_sink_from_name():
    with pytest.raises(
        KeyError,
        match="source or filter component class `pretty` not found in plugin `text`",
    ):
        bt2.ComponentSpec.from_named_plugin_and_component_class("text", "pretty")


def test_comp_spec_create_sink_from_object(pretty_comp_cls):
    with pytest.raises(
        TypeError,
        match="'_SinkComponentClassConst' is not a source or filter component class",
    ):
        bt2.ComponentSpec(pretty_comp_cls)


def test_comp_spec_create_from_object_with_params(dmesg_comp_cls):
    assert bt2.ComponentSpec(dmesg_comp_cls, {"salut": 23}).params["salut"] == 23


def test_comp_spec_create_from_name_with_params():
    spec = bt2.ComponentSpec.from_named_plugin_and_component_class(
        "text", "dmesg", {"salut": 23}
    )

    assert spec.params["salut"] == 23


def test_comp_spec_create_from_object_with_path_params(dmesg_comp_cls):
    assert bt2.ComponentSpec(dmesg_comp_cls, "a path").params["inputs"] == ["a path"]


def test_comp_spec_create_from_name_with_path_params():
    spec = bt2.ComponentSpec.from_named_plugin_and_component_class(
        "text", "dmesg", "a path"
    )

    assert spec.params["inputs"] == ["a path"]


def test_comp_spec_create_wrong_comp_cls_type():
    with pytest.raises(
        TypeError, match="'int' is not a source or filter component class"
    ):
        bt2.ComponentSpec(18)


def test_comp_spec_create_from_name_wrong_plugin_name_type():
    with pytest.raises(TypeError, match="'int' is not a 'str' object"):
        bt2.ComponentSpec.from_named_plugin_and_component_class(23, "compcls")


def test_comp_spec_create_from_name_non_existent_plugin():
    with pytest.raises(ValueError, match="no such plugin: this_plugin_does_not_exist"):
        bt2.ComponentSpec.from_named_plugin_and_component_class(
            "this_plugin_does_not_exist", "compcls"
        )


def test_comp_spec_create_from_name_wrong_comp_cls_name_type():
    with pytest.raises(TypeError, match="'int' is not a 'str' object"):
        bt2.ComponentSpec.from_named_plugin_and_component_class("utils", 190)


def test_comp_spec_create_wrong_params_type(dmesg_comp_cls):
    with pytest.raises(
        TypeError, match="cannot create value object from 'datetime' object"
    ):
        bt2.ComponentSpec(dmesg_comp_cls, params=datetime.datetime.now())


def test_comp_spec_create_from_name_wrong_params_type():
    with pytest.raises(
        TypeError, match="cannot create value object from 'datetime' object"
    ):
        bt2.ComponentSpec.from_named_plugin_and_component_class(
            "text", "dmesg", datetime.datetime.now()
        )


def test_comp_spec_create_wrong_log_level_type(dmesg_comp_cls):
    with pytest.raises(
        TypeError, match="'str' is not a '<enum 'LoggingLevel'>' object"
    ):
        bt2.ComponentSpec(dmesg_comp_cls, logging_level="banane")


def test_comp_spec_create_from_name_wrong_log_level_type():
    with pytest.raises(
        TypeError, match="'str' is not a '<enum 'LoggingLevel'>' object"
    ):
        bt2.ComponentSpec.from_named_plugin_and_component_class(
            "text", "dmesg", logging_level="banane"
        )


@pytest.fixture(scope="session")
def three_events_intersect_trace_dir(ctf_traces_dir):
    return ctf_traces_dir / "1/intersection/3eventsintersect"


def test_create_wrong_stream_intersection_mode_type(
    three_events_intersect_trace_dir,
):
    with pytest.raises(TypeError):
        bt2.TraceCollectionMessageIterator(
            [
                bt2.ComponentSpec.from_named_plugin_and_component_class(
                    "ctf", "fs", str(three_events_intersect_trace_dir)
                )
            ],
            stream_intersection_mode=23,
        )


def test_create_wrong_begin_type(three_events_intersect_trace_dir):
    with pytest.raises(TypeError):
        bt2.TraceCollectionMessageIterator(
            [
                bt2.ComponentSpec.from_named_plugin_and_component_class(
                    "ctf", "fs", str(three_events_intersect_trace_dir)
                )
            ],
            begin="hi",
        )


def test_create_wrong_end_type(three_events_intersect_trace_dir):
    with pytest.raises(TypeError):
        bt2.TraceCollectionMessageIterator(
            [
                bt2.ComponentSpec.from_named_plugin_and_component_class(
                    "ctf", "fs", str(three_events_intersect_trace_dir)
                )
            ],
            begin="lel",
        )


def test_create_begin_s(three_events_intersect_trace_dir):
    bt2.TraceCollectionMessageIterator(
        [
            bt2.ComponentSpec.from_named_plugin_and_component_class(
                "ctf", "fs", str(three_events_intersect_trace_dir)
            )
        ],
        begin=19457.918232,
    )


def test_create_end_s(three_events_intersect_trace_dir):
    bt2.TraceCollectionMessageIterator(
        [
            bt2.ComponentSpec.from_named_plugin_and_component_class(
                "ctf", "fs", str(three_events_intersect_trace_dir)
            )
        ],
        end=123.12312,
    )


def test_create_begin_datetime(three_events_intersect_trace_dir):
    bt2.TraceCollectionMessageIterator(
        [
            bt2.ComponentSpec.from_named_plugin_and_component_class(
                "ctf", "fs", str(three_events_intersect_trace_dir)
            )
        ],
        begin=datetime.datetime.now(),
    )


def test_create_end_datetime(three_events_intersect_trace_dir):
    bt2.TraceCollectionMessageIterator(
        [
            bt2.ComponentSpec.from_named_plugin_and_component_class(
                "ctf", "fs", str(three_events_intersect_trace_dir)
            )
        ],
        end=datetime.datetime.now(),
    )


def _event_msg_count(msgs):
    return sum(1 for msg in msgs if type(msg) is bt2._EventMessageConst)


def test_no_intersection(three_events_intersect_trace_dir):
    msgs = list(
        bt2.TraceCollectionMessageIterator(
            [
                bt2.ComponentSpec.from_named_plugin_and_component_class(
                    "ctf", "fs", str(three_events_intersect_trace_dir)
                )
            ]
        )
    )

    assert len(msgs) == 28
    assert _event_msg_count(msgs) == 8


def test_specs_not_list(three_events_intersect_trace_dir):
    msgs = list(
        bt2.TraceCollectionMessageIterator(
            bt2.ComponentSpec.from_named_plugin_and_component_class(
                "ctf", "fs", str(three_events_intersect_trace_dir)
            )
        )
    )

    assert len(msgs) == 28
    assert _event_msg_count(msgs) == 8


def test_custom_flt(three_events_intersect_trace_dir):
    msg_iter = bt2.TraceCollectionMessageIterator(
        bt2.ComponentSpec.from_named_plugin_and_component_class(
            "ctf", "fs", str(three_events_intersect_trace_dir)
        ),
        bt2.ComponentSpec.from_named_plugin_and_component_class(
            "utils", "trimmer", {"end": "13515309.000000075"}
        ),
    )

    assert _event_msg_count(msg_iter) == 5


def test_intersection(three_events_intersect_trace_dir):
    msgs = list(
        bt2.TraceCollectionMessageIterator(
            [
                bt2.ComponentSpec.from_named_plugin_and_component_class(
                    "ctf", "fs", str(three_events_intersect_trace_dir)
                )
            ],
            stream_intersection_mode=True,
        )
    )

    assert len(msgs) == 15
    assert _event_msg_count(msgs) == 3


def test_intersection_params(three_events_intersect_trace_dir):
    ev_msgs = [
        x
        for x in bt2.TraceCollectionMessageIterator(
            [
                bt2.ComponentSpec.from_named_plugin_and_component_class(
                    "ctf",
                    "fs",
                    {
                        "inputs": [str(three_events_intersect_trace_dir)],
                        "clock-class-offset-s": 1000,
                    },
                )
            ],
            stream_intersection_mode=True,
        )
        if type(x) is bt2._EventMessageConst
    ]

    assert len(ev_msgs) == 3
    assert ev_msgs[0].default_clock_snapshot.ns_from_origin == 13516309000000071
    assert ev_msgs[1].default_clock_snapshot.ns_from_origin == 13516309000000072
    assert ev_msgs[2].default_clock_snapshot.ns_from_origin == 13516309000000082


def test_no_intersection_two_traces(three_events_intersect_trace_dir):
    spec = bt2.ComponentSpec.from_named_plugin_and_component_class(
        "ctf", "fs", str(three_events_intersect_trace_dir)
    )

    msgs = list(bt2.TraceCollectionMessageIterator([spec, spec]))
    assert len(msgs) == 56
    assert _event_msg_count(msgs) == 16


def test_no_intersection_begin(three_events_intersect_trace_dir):
    count = _event_msg_count(
        bt2.TraceCollectionMessageIterator(
            [
                bt2.ComponentSpec.from_named_plugin_and_component_class(
                    "ctf", "fs", str(three_events_intersect_trace_dir)
                )
            ],
            begin=13515309.000000023,
        )
    )

    assert count == 6


def test_no_intersection_end(three_events_intersect_trace_dir):
    count = _event_msg_count(
        bt2.TraceCollectionMessageIterator(
            [
                bt2.ComponentSpec.from_named_plugin_and_component_class(
                    "ctf", "fs", str(three_events_intersect_trace_dir)
                )
            ],
            end=13515309.000000075,
        )
    )

    assert count == 5


def test_auto_src_comp_spec(three_events_intersect_trace_dir):
    msgs = list(
        bt2.TraceCollectionMessageIterator(
            [bt2.AutoSourceComponentSpec(str(three_events_intersect_trace_dir))]
        )
    )

    assert len(msgs) == 28
    assert _event_msg_count(msgs) == 8


def test_auto_src_comp_spec_list_of_strings(
    three_events_intersect_trace_dir,
):
    msgs = list(
        bt2.TraceCollectionMessageIterator([str(three_events_intersect_trace_dir)])
    )

    assert len(msgs) == 28
    assert _event_msg_count(msgs) == 8


def test_auto_src_comp_spec_string(three_events_intersect_trace_dir):
    msgs = list(
        bt2.TraceCollectionMessageIterator(str(three_events_intersect_trace_dir))
    )

    assert len(msgs) == 28
    assert _event_msg_count(msgs) == 8


@pytest.fixture(scope="session")
def nointersect_trace_dir(ctf_traces_dir):
    return ctf_traces_dir / "1/intersection/nointersect"


@pytest.fixture(scope="session")
def sequence_trace_dir(ctf_traces_dir):
    return ctf_traces_dir / "1/succeed/sequence"


def test_mixed_inputs(
    three_events_intersect_trace_dir, sequence_trace_dir, nointersect_trace_dir
):
    msgs = list(
        bt2.TraceCollectionMessageIterator(
            [
                str(three_events_intersect_trace_dir),
                bt2.AutoSourceComponentSpec(str(sequence_trace_dir)),
                bt2.ComponentSpec.from_named_plugin_and_component_class(
                    "ctf", "fs", str(nointersect_trace_dir)
                ),
            ]
        )
    )

    assert len(msgs) == 76
    assert _event_msg_count(msgs) == 24


def test_auto_src_comp_non_existent(sequence_trace_dir):
    with pytest.raises(
        RuntimeError,
        match="Some auto source component specs did not produce any component",
    ):
        bt2.TraceCollectionMessageIterator(
            [str(sequence_trace_dir), "/this/path/better/not/exist"]
        )


@pytest.fixture(scope="session")
def ascd_grouping_dir(data_dir):
    return data_dir / "auto-source-discovery/grouping"


@pytest.fixture
def ascd_grouping_env(ascd_grouping_dir):
    saved = os.environ["BABELTRACE_PLUGIN_PATH"]
    os.environ["BABELTRACE_PLUGIN_PATH"] += os.pathsep + str(ascd_grouping_dir)
    yield
    os.environ["BABELTRACE_PLUGIN_PATH"] = saved


def test_ascd_grouping(ascd_grouping_env, ascd_grouping_dir):
    msgs = [
        x
        for x in bt2.TraceCollectionMessageIterator(
            [
                bt2.AutoSourceComponentSpec("ABCDE"),
                bt2.AutoSourceComponentSpec(str(ascd_grouping_dir)),
            ]
        )
        if type(x) is bt2._StreamBeginningMessageConst
    ]

    assert len(msgs) == 8
    assert msgs[0].stream.name == "TestSourceABCDE: ABCDE"
    assert msgs[1].stream.name == "TestSourceExt: aaa1, aaa2, aaa3"
    assert msgs[2].stream.name == "TestSourceExt: bbb1, bbb2"
    assert msgs[3].stream.name == "TestSourceExt: ccc1"
    assert msgs[4].stream.name == "TestSourceExt: ccc2"
    assert msgs[5].stream.name == "TestSourceExt: ccc3"
    assert msgs[6].stream.name == "TestSourceExt: ccc4"
    assert msgs[7].stream.name == "TestSourceSomeDir: some-dir"


@pytest.fixture(scope="session")
def ascd_params_log_level_dir(data_dir):
    return data_dir / "auto-source-discovery/params-log-level"


@pytest.fixture
def ascd_params_log_level_env(ascd_params_log_level_dir):
    saved = os.environ["BABELTRACE_PLUGIN_PATH"]
    os.environ["BABELTRACE_PLUGIN_PATH"] += os.pathsep + str(ascd_params_log_level_dir)
    yield
    os.environ["BABELTRACE_PLUGIN_PATH"] = saved


@pytest.fixture(scope="session")
def dir_a(ascd_params_log_level_dir):
    return ascd_params_log_level_dir / "dir-a"


@pytest.fixture(scope="session")
def dir_b(ascd_params_log_level_dir):
    return ascd_params_log_level_dir / "dir-b"


@pytest.fixture(scope="session")
def dir_ab(ascd_params_log_level_dir):
    return ascd_params_log_level_dir / "dir-ab"


def _two_comps_from_one_spec(dir_ab, params, obj=None, logging_level=None):
    msgs = [
        x
        for x in bt2.TraceCollectionMessageIterator(
            [
                bt2.AutoSourceComponentSpec(
                    str(dir_ab), params=params, obj=obj, logging_level=logging_level
                )
            ]
        )
        if type(x) is bt2._StreamBeginningMessageConst
    ]

    assert len(msgs) == 2
    return msgs


def test_ascd_params_two_comps_from_one_spec(ascd_params_log_level_env, dir_ab):
    msgs = _two_comps_from_one_spec(
        dir_ab, params={"test-allo": "madame", "what": "test-params"}
    )

    assert msgs[0].stream.name == "TestSourceA: ('test-allo', 'madame')"
    assert msgs[1].stream.name == "TestSourceB: ('test-allo', 'madame')"


def test_ascd_obj_two_comps_from_one_spec(ascd_params_log_level_env, dir_ab):
    msgs = _two_comps_from_one_spec(dir_ab, params={"what": "python-obj"}, obj="deore")
    assert msgs[0].stream.name == "TestSourceA: deore"
    assert msgs[1].stream.name == "TestSourceB: deore"


def test_ascd_log_level_two_comps_from_one_spec(ascd_params_log_level_env, dir_ab):
    msgs = _two_comps_from_one_spec(
        dir_ab, params={"what": "log-level"}, logging_level=bt2.LoggingLevel.DEBUG
    )

    assert msgs[0].stream.name == "TestSourceA: {}".format(bt2.LoggingLevel.DEBUG)
    assert msgs[1].stream.name == "TestSourceB: {}".format(bt2.LoggingLevel.DEBUG)


def _two_comps_from_two_specs(
    dir_a,
    dir_b,
    params_a=None,
    params_b=None,
    obj_a=None,
    obj_b=None,
    logging_level_a=None,
    logging_level_b=None,
):
    msgs = [
        x
        for x in bt2.TraceCollectionMessageIterator(
            [
                bt2.AutoSourceComponentSpec(
                    str(dir_a),
                    params=params_a,
                    obj=obj_a,
                    logging_level=logging_level_a,
                ),
                bt2.AutoSourceComponentSpec(
                    str(dir_b),
                    params=params_b,
                    obj=obj_b,
                    logging_level=logging_level_b,
                ),
            ]
        )
        if type(x) is bt2._StreamBeginningMessageConst
    ]

    assert len(msgs) == 2
    return msgs


def test_ascd_params_two_comps_from_two_specs(ascd_params_log_level_env, dir_a, dir_b):
    msgs = _two_comps_from_two_specs(
        dir_a,
        dir_b,
        params_a={"test-allo": "madame", "what": "test-params"},
        params_b={"test-bonjour": "monsieur", "what": "test-params"},
    )

    assert msgs[0].stream.name == "TestSourceA: ('test-allo', 'madame')"
    assert msgs[1].stream.name == "TestSourceB: ('test-bonjour', 'monsieur')"


def test_ascd_obj_two_comps_from_two_specs(ascd_params_log_level_env, dir_a, dir_b):
    msgs = _two_comps_from_two_specs(
        dir_a,
        dir_b,
        params_a={"what": "python-obj"},
        params_b={"what": "python-obj"},
        obj_a="deore",
        obj_b="alivio",
    )

    assert msgs[0].stream.name == "TestSourceA: deore"
    assert msgs[1].stream.name == "TestSourceB: alivio"


def test_ascd_log_level_two_comps_from_two_specs(
    ascd_params_log_level_env, dir_a, dir_b
):
    msgs = _two_comps_from_two_specs(
        dir_a,
        dir_b,
        params_a={"what": "log-level"},
        params_b={"what": "log-level"},
        logging_level_a=bt2.LoggingLevel.DEBUG,
        logging_level_b=bt2.LoggingLevel.TRACE,
    )

    assert msgs[0].stream.name == "TestSourceA: {}".format(bt2.LoggingLevel.DEBUG)
    assert msgs[1].stream.name == "TestSourceB: {}".format(bt2.LoggingLevel.TRACE)


def _one_comp_from_one_spec_one_comp_from_both_1(
    dir_a,
    dir_ab,
    params_a=None,
    params_ab=None,
    obj_a=None,
    obj_ab=None,
    logging_level_a=None,
    logging_level_ab=None,
):
    msgs = [
        x
        for x in bt2.TraceCollectionMessageIterator(
            [
                bt2.AutoSourceComponentSpec(
                    str(dir_a),
                    params=params_a,
                    obj=obj_a,
                    logging_level=logging_level_a,
                ),
                bt2.AutoSourceComponentSpec(
                    str(dir_ab),
                    params=params_ab,
                    obj=obj_ab,
                    logging_level=logging_level_ab,
                ),
            ]
        )
        if type(x) is bt2._StreamBeginningMessageConst
    ]

    assert len(msgs) == 2
    return msgs


def test_ascd_params_one_comp_from_one_spec_one_comp_from_both_1(
    ascd_params_log_level_env, dir_a, dir_ab
):
    msgs = _one_comp_from_one_spec_one_comp_from_both_1(
        dir_a,
        dir_ab,
        params_a={"test-allo": "madame", "what": "test-params"},
        params_ab={"test-bonjour": "monsieur", "what": "test-params"},
    )

    assert (
        msgs[0].stream.name
        == "TestSourceA: ('test-allo', 'madame'), ('test-bonjour', 'monsieur')"
    )

    assert msgs[1].stream.name == "TestSourceB: ('test-bonjour', 'monsieur')"


def test_ascd_obj_one_comp_from_one_spec_one_comp_from_both_1(
    ascd_params_log_level_env, dir_a, dir_ab
):
    msgs = _one_comp_from_one_spec_one_comp_from_both_1(
        dir_a,
        dir_ab,
        params_a={"what": "python-obj"},
        params_ab={"what": "python-obj"},
        obj_a="deore",
        obj_ab="alivio",
    )

    assert msgs[0].stream.name == "TestSourceA: alivio"
    assert msgs[1].stream.name == "TestSourceB: alivio"


def test_ascd_log_level_one_comp_from_one_spec_one_comp_from_both_1(
    ascd_params_log_level_env, dir_a, dir_ab
):
    msgs = _one_comp_from_one_spec_one_comp_from_both_1(
        dir_a,
        dir_ab,
        params_a={"what": "log-level"},
        params_ab={"what": "log-level"},
        logging_level_a=bt2.LoggingLevel.DEBUG,
        logging_level_ab=bt2.LoggingLevel.TRACE,
    )

    assert msgs[0].stream.name == "TestSourceA: {}".format(bt2.LoggingLevel.TRACE)
    assert msgs[1].stream.name == "TestSourceB: {}".format(bt2.LoggingLevel.TRACE)


def _one_comp_from_one_spec_one_comp_from_both_2(
    dir_ab,
    dir_a,
    params_ab=None,
    params_a=None,
    obj_ab=None,
    obj_a=None,
    logging_level_ab=None,
    logging_level_a=None,
):
    msgs = [
        x
        for x in bt2.TraceCollectionMessageIterator(
            [
                bt2.AutoSourceComponentSpec(
                    str(dir_ab),
                    params=params_ab,
                    obj=obj_ab,
                    logging_level=logging_level_ab,
                ),
                bt2.AutoSourceComponentSpec(
                    str(dir_a),
                    params=params_a,
                    obj=obj_a,
                    logging_level=logging_level_a,
                ),
            ]
        )
        if type(x) is bt2._StreamBeginningMessageConst
    ]

    assert len(msgs) == 2
    return msgs


def test_ascd_params_one_comp_from_one_spec_one_comp_from_both_2(
    ascd_params_log_level_env, dir_a, dir_ab
):
    msgs = _one_comp_from_one_spec_one_comp_from_both_2(
        dir_ab,
        dir_a,
        params_ab={
            "test-bonjour": "madame",
            "test-salut": "les amis",
            "what": "test-params",
        },
        params_a={"test-bonjour": "monsieur", "what": "test-params"},
    )

    assert (
        msgs[0].stream.name
        == "TestSourceA: ('test-bonjour', 'monsieur'), ('test-salut', 'les amis')"
    )

    assert (
        msgs[1].stream.name
        == "TestSourceB: ('test-bonjour', 'madame'), ('test-salut', 'les amis')"
    )


def test_ascd_obj_one_comp_from_one_spec_one_comp_from_both_2(
    ascd_params_log_level_env, dir_a, dir_ab
):
    msgs = _one_comp_from_one_spec_one_comp_from_both_2(
        dir_ab,
        dir_a,
        params_ab={"what": "python-obj"},
        params_a={"what": "python-obj"},
        obj_ab="deore",
        obj_a="alivio",
    )

    assert msgs[0].stream.name == "TestSourceA: alivio"
    assert msgs[1].stream.name == "TestSourceB: deore"


def test_ascd_log_level_one_comp_from_one_spec_one_comp_from_both_2(
    ascd_params_log_level_env, dir_a, dir_ab
):
    msgs = _one_comp_from_one_spec_one_comp_from_both_2(
        dir_ab,
        dir_a,
        params_ab={"what": "log-level"},
        params_a={"what": "log-level"},
        logging_level_ab=bt2.LoggingLevel.DEBUG,
        logging_level_a=bt2.LoggingLevel.TRACE,
    )

    assert msgs[0].stream.name == "TestSourceA: {}".format(bt2.LoggingLevel.TRACE)
    assert msgs[1].stream.name == "TestSourceB: {}".format(bt2.LoggingLevel.DEBUG)


def test_ascd_obj_override_with_none(ascd_params_log_level_env, dir_a, dir_ab):
    msgs = [
        x
        for x in bt2.TraceCollectionMessageIterator(
            [
                bt2.AutoSourceComponentSpec(
                    str(dir_ab), params={"what": "python-obj"}, obj="deore"
                ),
                bt2.AutoSourceComponentSpec(
                    str(dir_a), params={"what": "python-obj"}, obj=None
                ),
            ]
        )
        if type(x) is bt2._StreamBeginningMessageConst
    ]

    assert len(msgs) == 2
    assert msgs[0].stream.name == "TestSourceA: None"
    assert msgs[1].stream.name == "TestSourceB: deore"


def test_ascd_obj_no_override_with_no_obj(ascd_params_log_level_env, dir_a, dir_ab):
    msgs = [
        x
        for x in bt2.TraceCollectionMessageIterator(
            [
                bt2.AutoSourceComponentSpec(
                    str(dir_ab), params={"what": "python-obj"}, obj="deore"
                ),
                bt2.AutoSourceComponentSpec(str(dir_a), params={"what": "python-obj"}),
            ]
        )
        if type(x) is bt2._StreamBeginningMessageConst
    ]

    assert len(msgs) == 2
    assert msgs[0].stream.name == "TestSourceA: deore"
    assert msgs[1].stream.name == "TestSourceB: deore"


@pytest.fixture(scope="session")
def metadata_syntax_error_trace_dir(ctf_traces_dir):
    return ctf_traces_dir / "1/fail/metadata-syntax-error"


def test_ascd_metadata_syntax_error(metadata_syntax_error_trace_dir):
    with pytest.raises(bt2._Error) as exc_info:
        bt2.TraceCollectionMessageIterator(
            [bt2.AutoSourceComponentSpec(str(metadata_syntax_error_trace_dir))]
        )

    assert (
        'At line 3 in metadata stream: syntax error, unexpected CTF_RSBRAC: token="]"'
        in str(exc_info.value[0])
    )
