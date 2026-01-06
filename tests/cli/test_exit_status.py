# SPDX-FileCopyrightText: 2019 EfficiOS Inc.
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import pytest
import bt_tests_cli_utils as btu_cli


def _run_exit_status_test(build_root_dir, data_dir, case):
    return btu_cli.run_cli(
        build_root_dir,
        ["-c", "src.test-exit-status.StatusSrc", btu_cli.CliParams({"case": case})],
        plugin_paths=[data_dir / "cli/exit-status"],
    )


class TestInterruptedGraph:
    @pytest.fixture(scope="class")
    def cli_run(self, data_dir, build_root_dir):
        return _run_exit_status_test(build_root_dir, data_dir, "INTERRUPTED")

    def test_exit_status(self, cli_run):
        assert cli_run.returncode == 2

    def test_stdout(self, cli_run):
        assert cli_run.stdout == ""


class TestErrorGraph:
    @pytest.fixture(scope="class")
    def cli_run(self, data_dir, build_root_dir):
        return _run_exit_status_test(build_root_dir, data_dir, "ERROR")

    def test_exit_status(self, cli_run):
        assert cli_run.returncode == 1

    def test_stdout(self, cli_run):
        assert cli_run.stdout == ""

    def test_stderr(self, cli_run):
        assert "TypeError: Raising type error" in cli_run.stderr


class TestStopGraph:
    @pytest.fixture(scope="class")
    def cli_run(self, data_dir, build_root_dir):
        return _run_exit_status_test(build_root_dir, data_dir, "STOP")

    def test_exit_status(self, cli_run):
        assert cli_run.returncode == 0

    def test_stdout(self, cli_run):
        assert cli_run.stdout == ""

    def test_stderr(self, cli_run):
        assert cli_run.stderr == ""
