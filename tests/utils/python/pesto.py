# SPDX-License-Identifier: MIT
#
# Copyright (C) 2023 Philippe Proulx <pproulx@efficios.com>
#
# pyright: strict, reportTypeCommentUsage=false

import re
import abc
import ast
import struct

from utils import typing_mod as _typing

_Any = _typing.Any
_Callable = _typing.Callable
_Dict = _typing.Dict
_List = _typing.List
_Match = _typing.Match
_NoReturn = _typing.NoReturn
_Optional = _typing.Optional
_Pattern = _typing.Pattern


# Any item.
class _Item:
    def __init__(self, line_no: int):
        self._line_no = line_no

    # Source line number of this item.
    @property
    def line_no(self):
        return self._line_no

    # Returns the size, in bytes, of this item.
    @property
    @abc.abstractmethod
    def size(self) -> int:
        ...


# A repeatable item.
class _RepableItem(_Item):
    pass


# Single byte.
class _Byte(_RepableItem):
    def __init__(self, val: int, line_no: int):
        super().__init__(line_no)
        self._val = val

    # Byte value.
    @property
    def val(self):
        return self._val

    @property
    def size(self):
        return 1

    def __repr__(self):
        return "_Byte({}, {})".format(hex(self._val), self._line_no)


# String (encoded following UTF-8).
class _Str(_RepableItem):
    def __init__(self, val: str, line_no: int):
        super().__init__(line_no)
        self._val = val

    # String value.
    @property
    def val(self):
        return self._val

    @property
    def size(self):
        return len(self._val.encode())

    def __repr__(self):
        return "_Str({}, {})".format(repr(self._val), self._line_no)


# Byte order.
class _Bo(_Item):
    @property
    def size(self):
        return 0


# Little-endian byte order.
class _LeBo(_Bo):
    def __repr__(self):
        return "_LeBo({})".format(self._line_no)


# Big-endian byte order.
class _BeBo(_Bo):
    def __repr__(self):
        return "_BeBo({})".format(self._line_no)


# Label.
class _Label(_Item):
    def __init__(self, name: str, line_no: int):
        super().__init__(line_no)
        self._name = name

    # Label name.
    @property
    def name(self):
        return self._name

    @property
    def size(self):
        return 0

    def __repr__(self):
        return "_Label({}, {})".format(repr(self._name), self._line_no)


# Offset.
class _Offset(_Item):
    def __init__(self, val: int, line_no: int):
        super().__init__(line_no)
        self._val = val

    # Offset value.
    @property
    def val(self):
        return self._val

    @property
    def size(self):
        return 0

    def __repr__(self):
        return "_Offset({}, {})".format(repr(self._val), self._line_no)


# Value, possibly needing more than one byte.
class _Val(_RepableItem):
    def __init__(self, expr: str, len: int, line_no: int):
        super().__init__(line_no)
        self._expr = expr
        self._len = len

    # Expression to evaluate.
    @property
    def expr(self):
        return self._expr

    # Length (bits).
    @property
    def len(self):
        return self._len

    @property
    def size(self):
        return self._len // 8

    def __repr__(self):
        return "_Val({}, {}, {})".format(
            repr(self._expr), repr(self._len), self._line_no
        )


# Group of items.
class _Group(_RepableItem):
    def __init__(self, items: _List[_Item], line_no: int):
        super().__init__(line_no)
        self._items = items

    # Contained items.
    @property
    def items(self):
        return self._items

    @property
    def size(self):
        return sum([item.size for item in self._items])

    def __repr__(self):
        return "_Group({}, {})".format(repr(self._items), self._line_no)


# Repetition item.
class _Rep(_Item):
    def __init__(self, item: _RepableItem, mul: int, line_no: int):
        super().__init__(line_no)
        self._item = item
        self._mul = mul

    # Item to repeat.
    @property
    def item(self):
        return self._item

    # Repetition multiplier.
    @property
    def mul(self):
        return self._mul

    @property
    def size(self):
        return self._item.size * self._mul

    def __repr__(self):
        return "_Rep({}, {}, {})".format(
            repr(self._item), repr(self._mul), self._line_no
        )


# A parsing error containing a message and an optional source line
# number.
class _ParseError(RuntimeError):
    def __init__(self, msg: str, line_no: int):
        super().__init__(msg)
        self._line_no = line_no

    # Source line number
    @property
    def line_no(self):
        return self._line_no


# Portable EfficiOS Sophisticated Textual Octets (PESTO) parser.
#
# The constructor accepts a PESTO input. After building, use the `res`
# property to get the resulting main group.
class _Parser:
    # Builds a parser to parse the PESTO input `pesto`, parsing
    # immediately.
    def __init__(self, pesto: str):
        self._pesto = self._remove_comments(pesto)
        self._at = 0
        self._level = 0
        self._line_no = 1
        self._parse()

    # Result (main group).
    @property
    def res(self):
        return self._res

    # Returns `True` if this parser is done parsing.
    def _is_done(self):
        return self._at == len(self._pesto)

    # Returns `True` if this parser isn't done parsing.
    def _isnt_done(self):
        return not self._is_done()

    # Removes the comments from the PESTO input `pesto` and returns the
    # transformed string.
    @staticmethod
    def _remove_comments(pesto: str):
        chars = []  # type: _List[str]
        i = 0

        while i < len(pesto):
            if pesto[i] == '"':
                # Skip literal strings first, which may contain the
                # comment character (`#`).
                chars.append(pesto[i])
                i += 1

                while i < len(pesto):
                    ch = pesto[i]
                    chars.append(ch)
                    i += 1

                    if ch == '"':
                        break
            elif pesto[i] == "#":
                # Comment until the next `#` or the next new line
                i += 1

                while i < len(pesto):
                    ch = pesto[i]
                    i += 1

                    if ch in ("#", "\n"):
                        break
            else:
                # Anything else
                chars.append(pesto[i])
                i += 1

        return "".join(chars)

    # Raises a parse error, creating it using the message `msg` and the
    # current line number.
    def _raise_error(self, msg: str) -> _NoReturn:
        raise _ParseError(msg, self._line_no)

    # Tries to make the pattern `pat` match the current substring,
    # returning the match object and updating `self._at` on success.
    def _try_parse_pat(self, pat: _Pattern[str]):
        # Match
        m = pat.match(self._pesto, self._at)  # type: _Optional[_Match[str]]

        if m is None:
            return

        # Skip matched string
        self._at += len(m.group(0))

        # Update line number
        self._line_no += m.group(0).count("\n")

        # Return match object
        return m

    # Expects the pattern `pat` to match the current substring,
    # returning the match object and updating `self._at` on success, or
    # raising a parse error with the message `error_msg` on error.
    def _expect_pat(self, pat: _Pattern[str], error_msg: str):
        # Match
        m = self._try_parse_pat(pat)

        if m is None:
            # No match: error
            self._raise_error(error_msg)

        # Return match object
        return m

    # Pattern for _skip_ws()
    _ws_pat = re.compile(r"\s*")

    # Skips as many whitespaces as possible.
    def _skip_ws(self):
        self._try_parse_pat(self._ws_pat)

    # Pattern for _skip_ws_and_sym()
    _sym_or_ws_pat = re.compile(r"[\s!@/\\?&:;.,+[\]_=|-]*")

    # Skips as many whitespaces and insignificant symbol characters as
    # possible.
    def _skip_ws_and_sym(self):
        self._try_parse_pat(self._sym_or_ws_pat)

    # Pattern for _try_parse_hex_byte()
    _nibble_pat = re.compile(r"[A-Fa-f0-9]")

    # Tries to parse a hexadecimal byte, returning a byte item on
    # success.
    def _try_parse_hex_byte(self):
        # Match initial nibble
        m_high = self._try_parse_pat(self._nibble_pat)

        if m_high is None:
            # No match
            return

        # Expect another nibble
        self._skip_ws_and_sym()
        m_low = self._expect_pat(
            self._nibble_pat, "Expecting another hexadecimal nibble"
        )

        # Return item
        return _Byte(int(m_high.group(0) + m_low.group(0), 16), self._line_no)

    # Patterns for _try_parse_bin_byte()
    _bin_byte_bit_pat = re.compile(r"[01]")
    _bin_byte_prefix_pat = re.compile(r"%")

    # Tries to parse a binary byte, returning a byte item on success.
    def _try_parse_bin_byte(self):
        # Match prefix
        if self._try_parse_pat(self._bin_byte_prefix_pat) is None:
            # No match
            return

        # Expect eight bits
        bits = []  # type: _List[str]

        for _ in range(8):
            self._skip_ws_and_sym()
            m = self._expect_pat(self._bin_byte_bit_pat, "Expecting a bit")
            bits.append(m.group(0))

        # Return item
        return _Byte(int("".join(bits), 2), self._line_no)

    # Patterns for _try_parse_dec_byte()
    _dec_byte_prefix_pat = re.compile(r"\$")
    _dec_byte_val_pat = re.compile(r"(?P<neg>-?)(?P<val>\d+)")

    # Tries to parse a decimal byte, returning a byte item on success.
    def _try_parse_dec_byte(self):
        # Match prefix
        if self._try_parse_pat(self._dec_byte_prefix_pat) is None:
            # No match
            return

        # Expect the value
        self._skip_ws()
        m = self._expect_pat(self._dec_byte_val_pat, "Expecting a decimal constant")

        # Compute value
        val = int(m.group("val")) * (-1 if m.group("neg") == "-" else 1)

        # Validate
        if val < -128 or val > 255:
            self._raise_error("Invalid decimal byte value {}".format(val))

        # Two's complement
        val = val % 256

        # Return item
        return _Byte(val, self._line_no)

    # Tries to parse a byte, returning a byte item on success.
    def _try_parse_byte(self):
        # Hexadecimal
        item = self._try_parse_hex_byte()

        if item is not None:
            return item

        # Binary
        item = self._try_parse_bin_byte()

        if item is not None:
            return item

        # Decimal
        item = self._try_parse_dec_byte()

        if item is not None:
            return item

    # Patterns for _try_parse_str()
    _str_prefix_suffix_pat = re.compile(r'"')
    _str_str_pat = re.compile(r'(?:(?:\\.)|[^"])*')

    # Strings corresponding to escape sequence characters
    _str_escape_seq_strs = {
        "0": "\0",
        "a": "\a",
        "b": "\b",
        "e": "\x1b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "\\": "\\",
        '"': '"',
    }

    # Tries to parse a string, returning a string item on success.
    def _try_parse_str(self):
        # Match prefix
        if self._try_parse_pat(self._str_prefix_suffix_pat) is None:
            # No match
            return

        # Actual string
        m = self._expect_pat(self._str_str_pat, "Expecting a string")

        # Expect end of string
        self._expect_pat(self._str_prefix_suffix_pat, 'Expecting `"`')

        # Replace escape sequences
        val = m.group(0)

        for ec in r"0abefnrtv\"":
            val = val.replace(r"\{}".format(ec), self._str_escape_seq_strs[ec])

        # Return item
        return _Str(val, self._line_no)

    # Patterns for _try_parse_group()
    _group_prefix_pat = re.compile(r"\(")
    _group_suffix_pat = re.compile(r"\)")

    # Tries to parse a group, returning a group item on success.
    def _try_parse_group(self):
        # Match prefix
        if self._try_parse_pat(self._group_prefix_pat) is None:
            # No match
            return

        # Parse items, updating the nesting level accordingly
        self._level += 1
        items = self._parse_items()
        self._level -= 1

        # Expect end of group
        self._skip_ws_and_sym()
        self._expect_pat(self._group_suffix_pat, "Expecting `)`")

        # Return item
        return _Group(items, self._line_no)

    # Patterns for _try_parse_val_and_len()
    _val_expr_pat = re.compile(r"([^}:]+):")
    _val_len_pat = re.compile(r"8|16|24|32|40|48|56|64")

    # Tries to parse a value and length, returning a value item on
    # success.
    def _try_parse_val_and_len(self):
        # Match
        m_expr = self._try_parse_pat(self._val_expr_pat)

        if m_expr is None:
            # No match
            return

        # Expect a length
        self._skip_ws()
        m_len = self._expect_pat(
            self._val_len_pat, "Expecting a length (multiple of eight bits)"
        )

        # Return item
        return _Val(
            m_expr.group(1).strip().replace("\n", " "),
            int(m_len.group(0)),
            self._line_no,
        )

    # Pattern for _try_parse_bo_name()
    _bo_pat = re.compile(r"le|be")

    # Tries to parse a byte order name, returning a byte order item on
    # success.
    def _try_parse_bo_name(self):
        # Match
        m = self._try_parse_pat(self._bo_pat)

        if m is None:
            # No match
            return

        # Return corresponding item
        if m.group(0) == "be":
            return _BeBo(self._line_no)
        else:
            assert m.group(0) == "le"
            return _LeBo(self._line_no)

    # Patterns for _try_parse_val_or_bo()
    _val_bo_prefix_pat = re.compile(r"\{")
    _val_bo_suffix_pat = re.compile(r"}")

    # Tries to parse a value or a byte order, returning an item on
    # success.
    def _try_parse_val_or_bo(self):
        # Match prefix
        if self._try_parse_pat(self._val_bo_prefix_pat) is None:
            # No match
            return

        self._skip_ws()

        # Value item?
        item = self._try_parse_val_and_len()

        if item is None:
            # Byte order item?
            item = self._try_parse_bo_name()

            if item is None:
                # At this point it's invalid
                self._raise_error("Expecting a byte order or a value")

        # Expect suffix
        self._skip_ws()
        self._expect_pat(self._val_bo_suffix_pat, "Expecting `}`")
        return item

    # Pattern for _try_parse_offset_val() and _try_parse_rep()
    _dec_const_pat = re.compile(r"\d+")

    # Tries to parse an offset value (after the initial `<`), returning
    # an offset item on success.
    def _try_parse_offset_val(self):
        # Match
        m = self._try_parse_pat(self._dec_const_pat)

        if m is None:
            # No match
            return

        # Return item
        return _Offset(int(m.group(0)), self._line_no)

    # Pattern for _try_parse_label_name()
    _label_name_pat = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")

    # Tries to parse a label name (after the initial `<`), returning a
    # label item on success.
    def _try_parse_label_name(self):
        # Match
        m = self._try_parse_pat(self._label_name_pat)

        if m is None:
            # No match
            return

        # Validate
        if m.group(0) == _icitte_name:
            self._raise_error("`{}` is a reserved label name".format(_icitte_name))

        # Return item
        return _Label(m.group(0), self._line_no)

    # Patterns for _try_parse_label_or_offset()
    _label_offset_prefix_pat = re.compile(r"<")
    _label_offset_suffix_pat = re.compile(r">")

    # Tries to parse a label or an offset, returning an item on success.
    def _try_parse_label_or_offset(self):
        # Match prefix
        if self._try_parse_pat(self._label_offset_prefix_pat) is None:
            # No match
            return

        self._skip_ws()

        # Validate current nesting level
        if self._level > 0:
            self._raise_error("Illegal label or offset within a group")

        # Offset item?
        item = self._try_parse_offset_val()

        if item is None:
            # Label item?
            item = self._try_parse_label_name()

            if item is None:
                # At this point it's invalid
                self._raise_error("Expecting a label name or an offset value")

        # Expect suffix
        self._skip_ws()
        self._expect_pat(self._label_offset_suffix_pat, "Expecting `>`")
        return item

    # Tries to parse a base item (anything except a repetition),
    # returning it on success.
    def _try_parse_base_item(self):
        self._skip_ws_and_sym()

        # Byte item?
        item = self._try_parse_byte()

        if item is not None:
            return item

        # String item?
        item = self._try_parse_str()

        if item is not None:
            return item

        # Value or byte order item?
        item = self._try_parse_val_or_bo()

        if item is not None:
            return item

        # Label or offset item?
        item = self._try_parse_label_or_offset()

        if item is not None:
            return item

        # Group item?
        item = self._try_parse_group()

        if item is not None:
            return item

    # Pattern for _try_parse_rep()
    _rep_prefix_pat = re.compile(r"\*")

    # Tries to parse a repetition, returning the multiplier on success,
    # or 1 otherwise.
    def _try_parse_rep(self):
        self._skip_ws()

        # Match prefix
        if self._try_parse_pat(self._rep_prefix_pat) is None:
            # No match
            return 1

        # Expect and return a decimal multiplier
        self._skip_ws()
        m = self._expect_pat(self._dec_const_pat, "Expecting a decimal multiplier")
        return int(m.group(0))

    # Tries to parse a repeatable item followed or not by a repetition,
    # returning an item on success.
    def _try_parse_item(self):
        # Parse a base item
        item = self._try_parse_base_item()

        if item is None:
            # No item
            return

        # Parse repetition if the base item is repeatable
        if isinstance(item, _RepableItem):
            rep = self._try_parse_rep()

            if rep == 0:
                # No item
                return
            elif rep > 1:
                # Convert to repetition item
                item = _Rep(item, rep, self._line_no)

        return item

    # Parses and returns items, skipping whitespaces and insignificant
    # symbols when allowed, and stopping at the first unknown character.
    def _parse_items(self) -> _List[_Item]:
        items = []  # type: _List[_Item]

        while self._isnt_done():
            # Try to parse item
            item = self._try_parse_item()

            if item is not None:
                # Append new item
                items.append(item)
                continue

            # Unknown at this point
            break

        return items

    # Parses the whole PESTO input, setting `self._res` to the main
    # group item on success.
    def _parse(self):
        if len(self._pesto.strip()) == 0:
            # Special case to make sure there's something to consume
            self._res = _Group([], self._line_no)
            return

        # Parse first level items
        items = self._parse_items()

        # Make sure there's nothing left
        self._skip_ws_and_sym()

        if self._isnt_done():
            self._raise_error("Unexpected character `{}`".format(self._pesto[self._at]))

        # Set main group item
        self._res = _Group(items, self._line_no)


# Label dictionary type.
_LabelsT = _Dict[str, int]


# The return type of parse().
class _ParseRes:
    def __init__(self, bytes: bytearray, labels: _LabelsT):
        self._bytes = bytes
        self._labels = labels

    # Generated data.
    @property
    def bytes(self):
        return self._bytes

    # Dictionary of new label names to their computed value.
    @property
    def labels(self):
        return self._labels


# Raises a parse error for the item `item`, creating it using the
# message `msg`.
def _raise_error_for_item(msg: str, item: _Item) -> _NoReturn:
    raise _ParseError(msg, item.line_no)


# The `ICITTE` reserved name.
_icitte_name = "ICITTE"


# Value expression validator.
class _ExprValidator(ast.NodeVisitor):
    def __init__(self, item: _Val, labels: _LabelsT):
        self._item = item
        self._labels = labels

    def generic_visit(self, node: ast.AST):
        # TODO: Technically incorrect because a name node may be correct
        # in some contexts, for example `abs` in `abs(-my_label)`.
        if type(node) is ast.Name:
            # Make sure the name refers to a known label name
            if node.id != _icitte_name and node.id not in self._labels:
                _raise_error_for_item(
                    "Unknown label name `{}` in expression `{}`".format(
                        node.id, self._item.expr
                    ),
                    self._item,
                )

        # TODO: Restrict the set of allowed node types

        super().generic_visit(node)


# Generator of data and labels from a group item.
#
# Generation happens in memory at construction time. After building, use
# the `bytes` and `labels` properties to get the resulting data and
# labels.
class _Gen:
    def __init__(self, group: _Group, labels: _LabelsT):
        self._labels = labels.copy()
        self._labels[_icitte_name] = 0
        self._resolve_labels(group)
        self._gen(group)

    # Generated data
    @property
    def bytes(self):
        return self._bytes

    # Updated labels
    @property
    def labels(self):
        return self._labels

    def _resolve_labels(self, group: _Group):
        offset = 0

        for item in group.items:
            if type(item) is _Offset:
                offset = item.val
            elif type(item) is _Label:
                assert item.name != _icitte_name

                if item.name in self._labels:
                    _raise_error_for_item(
                        "Duplicate label name `{}`".format(item.name), item
                    )

                self._labels[item.name] = offset

            offset += item.size

    def _handle_byte_item(self, item: _Byte):
        self._bytes.append(item.val)
        self._offset += 1

    def _handle_str_item(self, item: _Str):
        str_bytes = item.val.encode()
        self._bytes += str_bytes
        self._offset += len(str_bytes)

    def _handle_be_bo_item(self, item: _BeBo):
        self._bo_is_be = True

    def _handle_le_bo_item(self, item: _LeBo):
        self._bo_is_be = False

    def _handle_val_item(self, item: _Val):
        # Create an expression node from the expression string
        try:
            expr = ast.parse(item.expr, mode="eval")
        except SyntaxError:
            _raise_error_for_item(
                "Invalid expression `{}`: invalid syntax".format(item.expr), item
            )

        # Validate the node and its children
        _ExprValidator(item, self._labels).visit(expr)

        # Update the reserved `ICITTE` name
        self._labels[_icitte_name] = self._offset

        # Compile and evaluate expression node
        val = eval(compile(expr, "", "eval"), None, self._labels)

        # Validate result
        if type(val) is not int:
            _raise_error_for_item(
                "Invalid expression `{}`: unexpected result type".format(item.expr),
                item,
            )

        # Encode result on 64 bits (to extend the sign bit whatever the
        # value of `item.len`).
        if self._bo_is_be is None:
            _raise_error_for_item(
                "Current byte order isn't defined at first value (`{}`) to encode".format(
                    item.expr
                ),
                item,
            )

        bo_prefix = ">" if self._bo_is_be else "<"
        fmt = "Q" if val >= 0 else "q"
        bytes = struct.pack("{}{}".format(bo_prefix, fmt), val)

        # Keep only the requested length
        len_bytes = item.len // 8

        if self._bo_is_be:
            # Big endian: keep last bytes
            bytes = bytes[-len_bytes:]
        else:
            # Little endian: keep first bytes
            bytes = bytes[:len_bytes]

        # Append to current bytes and update offset
        self._bytes += bytes
        self._offset += len(bytes)

    def _handle_group_item(self, group_item: _Group):
        for item in group_item.items:
            self._handle_item(item)

    def _handle_rep_item(self, item: _Rep):
        for _ in range(item.mul):
            self._handle_item(item.item)

    def _handle_offset_item(self, item: _Offset):
        self._offset = item.val

    def _handle_item(self, item: _Item):
        if type(item) in self._item_handlers:
            self._item_handlers[type(item)](item)

    def _gen(self, group: _Group):
        # Initial state
        self._offset = 0
        self._bytes = bytearray()
        self._bo_is_be = None

        # Item handlers
        self._item_handlers = {
            _Byte: self._handle_byte_item,
            _Str: self._handle_str_item,
            _BeBo: self._handle_be_bo_item,
            _LeBo: self._handle_le_bo_item,
            _Val: self._handle_val_item,
            _Group: self._handle_group_item,
            _Rep: self._handle_rep_item,
            _Offset: self._handle_offset_item,
        }  # type: _Dict[type, _Callable[[_Any], None]]

        # Handle the group item
        self._handle_item(group)

        # Remove the reserved `ICITTE` label (the public `labels`
        # property returns `self._labels`).
        del self._labels[_icitte_name]


# Returns a `_ParseRes` instance containing the bytes encoded by the
# input string `pesto`.
#
# `labels` is a dictionary of initial label names (valid Python names)
# to integral values. A label name must not be the reserved name
# `ICITTE`. There must be no labels in `pesto` sharing a name with any of
# the keys of `labels`.
#
# The format of `pesto`, named PESTO (Portable EfficiOS Sophisticated
# Textual Octets), is as such:
#
# • Whitespaces are ignored between items.
#
# • Some insignificant symbol characters are ignored.
#
# • Anything between `#` and a following `#` on the same line, or
#   between `#` and the end of the line, including those `#` characters,
#   is ignored (comment).
#
# • The grammar, without comments, is as such (`pesto` is expected to
#   match `ITEMS`):
#
#   ITEMS:
#       (
#         ((BYTE | STR | VAL | GROUP) (`*` POSDECVAL) ?) |
#         BO | LABEL | OFFSET | SYMS
#       ) *
#
#       Any byte, string, value, or group item may be followed by `*`
#       and some constant integer `POSDECVAL` to repeat the item
#       `POSDECVAL` times.
#
#   SYMS:
#       [!@/\\?&:;.,+[\]_=|-] *
#
#       Sequence of insignificant symbol characters.
#
#   BYTE:
#       HEXBYTE | BINBYTE | DECBYTE
#
#       Represents the value of a single byte.
#
#   HEXBYTE:
#       [A-Fa-f0-9] SYMS [A-Fa-f0-9]
#
#       Two consecutive hexits represent the value of a single byte
#       in hexadecimal.
#
#       Example: `8f`, `9:9`.
#
#   BINBYTE:
#       `%` SYMS [01] SYMS [01] SYMS [01] SYMS [01] SYMS
#                [01] SYMS [01] SYMS [01] SYMS [01]
#
#       Eight consecutive bits after the `%` prefix represent the value
#       of a single byte in binary.
#
#       Examples: `%0100_1100`, `% 1011.[01] 10`.
#
#   DECBYTE:
#       `$` DECVAL
#
#       A decimal constant after the `$` prefix represent the value of a
#       single byte in decimal. `DECVAL` must be in the [-128, 255]
#       range.
#
#       Examples: `$192`, `$ -101`.
#
#   STR:
#       `"` [^"] * `"`
#
#       A string between double quotes is encoded as UTF-8 bytes,
#       _without_ any implicit trailing null byte.
#
#       Example: `"hello world"`.
#
#   VAL:
#       `{` PYEXPR `:` LEN `}`
#
#       Represents an integral value, as computed by evaluating
#       `PYEXPR`, encoded using the current byte order (see `BO`).
#
#       In `PYEXPR`, the reserved `ICITTE` name refers to the current
#       offset (see `OFFSET`), before encoding the value of `PYEXPR`.
#
#       The numeric suffix `LEN` indicates the length of the value to
#       encode in bits.
#
#       No `SYMS` allowed between `{` and `}`.
#
#       Examples: `{0x1000 + my_label * 8 : 32}`, `{meow-mix:16}`.
#
#   PYEXPR:
#       Any valid arithmetic Python expression. It may include label
#       names (see `LABEL`) as Python names referring to the label
#       values.
#
#       The `ICITTE` name is reserved.
#
#   LEN:
#       `8` | `16` | `24` | `32` | `40` | `48` | `56` | `64`
#
#   POSDECVAL:
#       [0-9] +
#
#       A positive decimal constant (no `SYMS` allowed).
#
#   DECVAL:
#       POSDECVAL | (`-` [0-9] +)
#
#       A decimal constant, possibly negative (no `SYMS` or whitespaces
#       allowed).
#
#       Examples: `199`, `-48859`.
#
#   GROUP:
#       `(` (((BYTE | STR | VAL | GROUP) (`*` POSDECVAL) ?) | BO | SYMS) * `)`
#
#       A sequence of items, except labels (`LABEL`) and offsets
#       (`OFFSET`).
#
#       Any byte, string, value, or nested group item may be followed by
#       `*` and some constant integer `POSDECVAL` to repeat the item
#       `POSDECVAL` times.
#
#   BO:
#       `{` (`be` | `le`) `}`
#
#       `{be}` sets the current byte order to big endian while `{le}`
#       sets it to little endian (see `VAL`).
#
#       No `SYMS` allowed between `{` and `}`.
#
#   LABEL:
#       `<` PYNAME `>`
#
#       `PYNAME` must not be `ICITTE` (reserved name).
#
#       No `SYMS` allowed between `<` and `>`.
#
#       Example: `<here>`.
#
#   PYNAME:
#       Any valid Python name.
#
#   OFFSET:
#       `<` POSDECVAL `>`
#
#       Sets the current offset to `POSDECVAL`, impacting label value
#       computation (see `LABEL`).
#
#       No `SYMS` allowed between `<` and `>`.
#
#       Example: `<380>`.
#
# There's no initial byte order, so there must be a `BO` item before the
# first `VAL` item, if any.
#
# Raises `_ParseError` on any parsing error.
def parse(pesto: str, labels: _Optional[_LabelsT] = None):
    if labels is None:
        labels = {}

    gen = _Gen(_Parser(pesto).res, labels)
    return _ParseRes(gen.bytes, gen.labels)
