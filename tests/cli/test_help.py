# SPDX-FileCopyrightText: 2019 EfficiOS Inc.
# SPDX-FileCopyrightText: 2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

import pytest
import bt_tests_cli_utils as btu_cli


# Test `help` command with a working plugin name.
class TestHelpPlugin:
    @pytest.fixture(scope="class")
    def result(self, build_root_dir):
        return btu_cli.run_cli(build_root_dir, ["help", "ctf"])

    def test_exit_status(self, result):
        assert result.returncode == 0

    def test_stdout_contains_expected_output(self, result):
        assert "Description: CTF input and output" in result.stdout

    def test_stderr_is_empty(self, result):
        assert result.stderr == ""


# Test `help` command with a working component class name.
class TestHelpComponentClass:
    @pytest.fixture(scope="class")
    def result(self, build_root_dir):
        return btu_cli.run_cli(build_root_dir, ["help", "src.ctf.fs"])

    def test_exit_status(self, result):
        assert result.returncode == 0

    def test_stdout_contains_expected_output(self, result):
        assert "Description: Read CTF traces from the file system." in result.stdout

    def test_stderr_is_empty(self, result):
        assert result.stderr == ""


# Test `help` command without a parameter.
class TestHelpNoParameter:
    @pytest.fixture(scope="class")
    def result(self, build_root_dir):
        return btu_cli.run_cli(build_root_dir, ["help"])

    def test_exit_status_is_failure(self, result):
        assert result.returncode != 0

    def test_stderr_contains_expected_error(self, result):
        assert "Missing plugin name or component class descriptor." in result.stderr

    def test_stdout_is_empty(self, result):
        assert result.stdout == ""


# Test `help` command with too many parameters.
class TestHelpTooManyParameters:
    @pytest.fixture(scope="class")
    def result(self, build_root_dir):
        return btu_cli.run_cli(build_root_dir, ["help", "ctf", "fs"])

    def test_exit_status_is_failure(self, result):
        assert result.returncode != 0

    def test_stderr_contains_expected_error(self, result):
        assert (
            "Extraneous command-line argument specified to `help` command:"
            in result.stderr
        )

    def test_stdout_is_empty(self, result):
        assert result.stdout == ""


# Test `help` command with an unknown plugin name.
class TestHelpUnknownPlugin:
    @pytest.fixture(scope="class")
    def result(self, build_root_dir):
        return btu_cli.run_cli(build_root_dir, ["help", "zigotos"])

    def test_exit_status_is_failure(self, result):
        assert result.returncode != 0

    def test_stderr_contains_expected_error(self, result):
        assert 'Cannot find plugin: plugin-name="zigotos"' in result.stderr

    def test_stdout_is_empty(self, result):
        assert result.stdout == ""


# Test `help` command with an unknown component class name (but known plugin).
class TestHelpUnknownComponentClass:
    @pytest.fixture(scope="class")
    def result(self, build_root_dir):
        return btu_cli.run_cli(build_root_dir, ["help", "src.ctf.bob"])

    def test_exit_status_is_failure(self, result):
        assert result.returncode != 0

    def test_stderr_contains_expected_error(self, result):
        assert (
            'Cannot find component class: plugin-name="ctf", comp-cls-name="bob", comp-cls-type=SOURCE'
            in result.stderr
        )

    def test_stdout_contains_plugin_help(self, result):
        assert "Description: CTF input and output" in result.stdout


# Test `help` command with an unknown component class plugin.
class TestHelpUnknownComponentClassPlugin:
    @pytest.fixture(scope="class")
    def result(self, build_root_dir):
        return btu_cli.run_cli(build_root_dir, ["help", "src.bob.fs"])

    def test_exit_status_is_failure(self, result):
        assert result.returncode != 0

    def test_stderr_contains_expected_error(self, result):
        assert 'Cannot find plugin: plugin-name="bob"' in result.stderr

    def test_stdout_is_empty(self, result):
        assert result.stdout == ""
