# SPDX-FileCopyrightText: 2020-2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: MIT

# pyright: strict, reportMissingTypeStubs=false, reportTypeCommentUsage=false

import os
import re
import sys
import signal
import typing
import logging
import pathlib
import subprocess
from typing import Any, Set, List, Tuple, Optional

import tjson
import pytest
import bt_tests_utils as btu

_logger = logging.getLogger(__name__)


# Helper function to access dynamic `config` attribute while satisfying
# the type checker.
def _config_build_root_dir(config: "pytest.Config") -> pathlib.Path:
    return getattr(config, "build_root_dir")


# Condition trigger descriptor (base).
class _CondTriggerDescriptor:
    def __init__(self, trigger_name: str, cond_id: str):
        self._trigger_name = trigger_name
        self._cond_id = cond_id

    @property
    def trigger_name(self) -> str:
        return self._trigger_name

    @property
    def cond_id(self) -> str:
        return self._cond_id


# Precondition trigger descriptor.
class _PreCondTriggerDescriptor(_CondTriggerDescriptor):
    @property
    def type_str(self) -> str:
        return "pre"


# Postcondition trigger descriptor.
class _PostCondTriggerDescriptor(_CondTriggerDescriptor):
    @property
    def type_str(self) -> str:
        return "post"


# Parses condition trigger descriptors from JSON array.
def _cond_trigger_descriptors_from_json(
    json_descr_array: tjson.ArrayVal,
) -> List[_CondTriggerDescriptor]:
    descriptors = []  # type: List[_CondTriggerDescriptor]
    descriptor_names = set()  # type: Set[str]

    for json_descr in json_descr_array.iter(tjson.ObjVal):
        trigger_name = json_descr.at("name", tjson.StrVal).val

        if trigger_name in descriptor_names:
            raise ValueError(
                "Duplicate condition trigger name `{}`".format(trigger_name)
            )

        cond_id = json_descr.at("cond-id", tjson.StrVal).val

        if cond_id.startswith("pre"):
            cond_type = _PreCondTriggerDescriptor
        elif cond_id.startswith("post"):
            cond_type = _PostCondTriggerDescriptor
        else:
            raise ValueError("Invalid condition ID `{}`".format(cond_id))

        descriptors.append(cond_type(trigger_name, cond_id))
        descriptor_names.add(trigger_name)

    return descriptors


class _CondTriggerTestItem(btu.PytestItem):
    def __init__(
        self,
        *,
        descriptor: _CondTriggerDescriptor,
        conds_triggers_bin: pathlib.Path,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self._descriptor = descriptor
        self._conds_triggers_bin = conds_triggers_bin

    def runtest(self) -> None:
        timeout = 5

        # Execute:
        #
        #     $ conds-triggers run <trigger-name>
        #
        # where `<trigger-name>` is the descriptor trigger name.
        _logger.info(
            "Running the condition trigger `{}`".format(self._descriptor.trigger_name)
        )

        try:
            result = btu.run(
                _config_build_root_dir(self.config),
                self._conds_triggers_bin,
                ["run", self._descriptor.trigger_name],
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            _logger.error(
                "Condition trigger `{}` hung for {} seconds".format(
                    self._descriptor.trigger_name, timeout
                )
            )
            raise _CondTriggerTestException(
                self._descriptor, "Process hung for {} seconds".format(timeout)
            )

        _logger.debug(result.stderr)

        # Assert that the program aborted (only available on POSIX)
        if os.name == "posix":
            _logger.debug("Return code: {}".format(result.returncode))

            if result.returncode != -int(signal.SIGABRT):
                raise _CondTriggerTestException(
                    self._descriptor,
                    "Expected return code {} (SIGABRT); got {}".format(
                        -int(signal.SIGABRT), result.returncode
                    ),
                    result,
                )

        # Assert that the standard error text contains the condition ID
        if "Condition ID: `{}`".format(self._descriptor.cond_id) not in result.stderr:
            raise _CondTriggerTestException(
                self._descriptor,
                "Expected condition ID `{}` not found in standard error stream".format(
                    self._descriptor.cond_id
                ),
                result,
            )

    def reportinfo(self) -> Tuple[pathlib.Path, None, str]:
        return self.path, None, self.name

    def repr_failure(
        self,
        excinfo: "pytest.ExceptionInfo[BaseException]",
        style: Any = None,
    ) -> Any:
        if isinstance(excinfo.value, _CondTriggerTestException):
            return excinfo.value.format_output()

        return super().repr_failure(excinfo, style)


class _CondTriggerTestException(Exception):
    def __init__(
        self,
        descriptor: _CondTriggerDescriptor,
        message: str,
        result: Optional["subprocess.CompletedProcess[str]"] = None,
    ):
        message = message.strip()

        super().__init__(
            "Condition trigger test failed for `{}`: {}".format(
                descriptor.trigger_name, message
            )
        )
        self._descriptor = descriptor
        self._message = message
        self._result = result

    def format_output(self) -> str:
        output = [
            "Trigger: `{}`".format(self._descriptor.trigger_name),
            "Condition ID: `{}`".format(self._descriptor.cond_id),
            "Error: {}".format(self._message),
        ]

        if self._result is not None:
            if self._result.stdout:
                output.append("\n⚠️ Standard output:")
                output.append(self._result.stdout)

            if self._result.stderr:
                output.append("\n⚠️ Standard error:")
                output.append(self._result.stderr)

        return "\n".join(output).strip()


class _CondTriggersTestFile(btu.PytestFile):
    @staticmethod
    def _normalize_trigger_name(trigger_name: str) -> str:
        return "test_" + re.sub(r"\W", "_", trigger_name)

    def collect(self) -> List[_CondTriggerTestItem]:
        # Build the path to the `conds-triggers` binary and make sure
        # it exists.
        conds_triggers_bin = btu.exe_path(
            btu.build_dir_of_source_file(_config_build_root_dir(self.config), __file__)
            / "conds-triggers"
        )

        # Skip if the binary doesn't exist
        if not conds_triggers_bin.exists():
            pytest.skip(
                "`{}` binary doesn't exist".format(conds_triggers_bin),
                allow_module_level=True,
            )
        else:
            assert os.access(conds_triggers_bin, os.X_OK)

        # Create test items
        items = []  # type: List[_CondTriggerTestItem]
        _logger.info("Listing condition triggers from `{}`".format(conds_triggers_bin))

        for descriptor in _cond_trigger_descriptors_from_json(
            tjson.loads(
                btu.run(
                    _config_build_root_dir(self.config),
                    conds_triggers_bin,
                    ["list"],
                ).stdout,
                tjson.ArrayVal,
            )
        ):
            _logger.info(
                "Adding test item for condition trigger `{}`".format(
                    descriptor.trigger_name
                )
            )
            items.append(
                _CondTriggerTestItem.from_parent(  # pyright: ignore[reportUnknownMemberType]
                    name=self._normalize_trigger_name(descriptor.trigger_name),
                    parent=self,
                    descriptor=descriptor,
                    conds_triggers_bin=conds_triggers_bin,
                )
            )

        return items


# pytest hook.
def _pytest_collect_file(
    file_path: pathlib.Path, parent: "pytest.Collector"
) -> Optional[_CondTriggersTestFile]:
    if file_path.name == "conds-triggers.cpp":
        return typing.cast(
            _CondTriggersTestFile,
            _CondTriggersTestFile.from_parent(parent=parent, path=file_path),
        )

    return None


btu.install_pytest_collect_file(sys.modules[__name__], _pytest_collect_file)
