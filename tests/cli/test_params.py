# SPDX-FileCopyrightText: 2019 Simon Marchi <simon.marchi@efficios.com>
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import pytest
import bt_tests_utils as btu
import bt_tests_cli_utils as btu_cli


@pytest.mark.parametrize(
    ["params_str", "expected_output"],
    [
        pytest.param(
            "a=null,b=nul,c=NULL",
            "{a=None, b=None, c=None}",
            id="null",
        ),
        pytest.param(
            "a=true,b=TRUE,c=yes,d=YES,e=false,f=FALSE,g=no,h=NO",
            "{a=True, b=True, c=True, d=True, e=False, f=False, g=False, h=False}",
            id="bool",
        ),
        pytest.param(
            "a=0b110, b=022, c=22, d=0x22",
            "{a=6, b=18, c=22, d=34}",
            id="signed-integer",
        ),
        pytest.param(
            "a=+0b110, b=+022, c=+22, d=+0x22",
            "{a=6u, b=18u, c=22u, d=34u}",
            id="unsigned-integer",
        ),
        pytest.param(
            'a="avril lavigne", b=patata, c="This\\"is\\\\escaped"',
            '{a=avril lavigne, b=patata, c=This"is\\escaped}',
            id="string",
        ),
        pytest.param(
            "a=1.234, b=17., c=.28, d=-18.28",
            "{a=1.2340000, b=17.0000000, c=0.2800000, d=-18.2800000}",
            id="float",
        ),
        pytest.param(
            "a=10.5e6, b=10.5E6, c=10.5e-6, d=10.5E-6",
            "{a=10500000.0000000, b=10500000.0000000, c=0.0000105, d=0.0000105}",
            id="float-scientific-notation",
        ),
        pytest.param(
            'a=[1, [["hi",]]]',
            "{a=[1, [[hi]]]}",
            id="array",
        ),
        pytest.param(
            'a=4,a={},b={salut="la gang",comment="ca va",oh={x=2}}',
            "{a={}, b={comment=ca va, oh={x=2}, salut=la gang}}",
            id="map",
        ),
    ],
)
def test_params(build_root_dir, params_str, expected_output):
    res = btu_cli.run_cli(
        build_root_dir,
        [
            "-c",
            "src.text.dmesg",
            "-c",
            "sink.params.SinkThatPrintsParams",
            "--params",
            params_str,
        ],
        plugin_paths=[btu.this_src_dir(__file__)],
        check=True,
    )

    assert res.stdout.strip() == expected_output
