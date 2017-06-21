#!/usr/bin/env python3

import binascii
import sys


class InvalidAxError(Exception):

    def __init__(self, msg, offset):
        super().__init__(msg)
        self._offset = offset

    @property
    def offset(self):
        return self._offset


class BaseOp:

    def __init__(self, offset):
        self._offset = offset

    @property
    def offset(self):
        return self._offset

    def __repr__(self):
        cls_name = type(self).__name__
        return '{}()'.format(cls_name)


class AddOp(BaseOp):
    pass


class SubOp(BaseOp):
    pass


class MulOp(BaseOp):
    pass


class RemSignedOp(BaseOp):
    pass


class RemUnsignedOp(BaseOp):
    pass


class LeftShiftOp(BaseOp):
    pass


class RightSignedShiftOp(BaseOp):
    pass


class RightUnsignedShiftOp(BaseOp):
    pass


class LogNotOp(BaseOp):
    pass


class AndOp(BaseOp):
    pass


class OrOp(BaseOp):
    pass


class XorOp(BaseOp):
    pass


class EqualOp(BaseOp):
    pass


class LessSignedOp(BaseOp):
    pass


class LessUnsignedOp(BaseOp):
    pass


class ExtendBaseOp(BaseOp):

    def __init__(self, ax_ptr, n_bits):
        super().__init__(ax_ptr)
        self._n_bits = n_bits

    @property
    def n_bits(self):
        return self._n_bits

    def __repr__(self):
        cls_name = type(self).__name__
        return '{}(n_bits={})'.format(cls_name,
                                      self.n_bits)


class SignExtendOp(ExtendBaseOp):
    pass


class ZeroExtendOp(ExtendBaseOp):
    pass


class Ref8Op(BaseOp):
    pass


class Ref16Op(BaseOp):
    pass


class Ref32Op(BaseOp):
    pass


class Ref64Op(BaseOp):
    pass


class GotoBaseOp(BaseOp):

    def __init__(self, ax_ptr, dest):
        super().__init__(ax_ptr)
        self._dest = dest

    @property
    def dest(self):
        return self._dest

    def __repr__(self):
        cls_name = type(self).__name__
        return '{}(dest={})'.format(cls_name, self.dest)


class GotoOp(GotoBaseOp):
    pass


class IfGotoOp(GotoBaseOp):
    pass


class SwapOp(BaseOp):
    pass


class GetVOp(BaseOp):

    def __init__(self, ax_ptr, tsv):
        super().__init__(ax_ptr)
        self._tsv = tsv

    @property
    def tsv(self):
        return self._tsv

    def __repr__(self):
        return 'GetV(tsv={})'.format(self.tsv)


class ConstBaseOp(BaseOp):

    def __init__(self, ax_ptr, operand):
        super().__init__(ax_ptr)
        self._operand = operand

    @property
    def operand(self):
        return self._operand

    def __repr__(self):
        cls_name = type(self).__name__
        return '{}(operand={} {})'.format(cls_name,
                                          self.operand,
                                          hex(self.operand))


class Const8Op(ConstBaseOp):
    pass


class Const16Op(ConstBaseOp):
    pass


class Const32Op(ConstBaseOp):
    pass


class Const64Op(ConstBaseOp):
    pass


class EndOp(BaseOp):
    pass


class XrefBaseOp(BaseOp):
    def __init__(self, ax_ptr, addr_space):
        super().__init__(ax_ptr)
        self._addr_space = addr_space

    @property
    def addr_space(self):
        return self._addr_space

    def __repr__(self):
        cls_name = type(self).__name__
        return '{}(addr_space={})'.format(cls_name, self.addr_space)


class Xref8Op(XrefBaseOp):
    def __init__(self, ax_ptr, addr_space):
        super().__init__(ax_ptr, addr_space)


class Xref16Op(XrefBaseOp):
    def __init__(self, ax_ptr, addr_space):
        super().__init__(ax_ptr, addr_space)


class Xref32Op(XrefBaseOp):
    def __init__(self, ax_ptr, addr_space):
        super().__init__(ax_ptr, addr_space)


class Xref64Op(XrefBaseOp):
    def __init__(self, ax_ptr, addr_space):
        super().__init__(ax_ptr, addr_space)


class RegOp(BaseOp):

    def __init__(self, ax_ptr, reg):
        super().__init__(ax_ptr)
        self._reg = reg

    @property
    def reg(self):
        return self._reg

    def __repr__(self):
        return 'RegOp(reg={} {})'.format(self.reg,
                                         hex(self._reg))


class AxDisas:

    def __init__(self):
        self._handlers = {
            0x02: self._parse_add,
            0x03: self._parse_sub,
            0x04: self._parse_mul,
            0x07: self._parse_rem_signed,
            0x08: self._parse_rem_unsigned,
            0x09: self._parse_left_shift,
            0x0a: self._parse_right_signed_shift,
            0x0b: self._parse_right_unsigned_shift,
            0x0e: self._parse_log_not,
            0x0f: self._parse_and,
            0x10: self._parse_or,
            0x11: self._parse_xor,
            0x13: self._parse_equal,
            0x14: self._parse_less_signed,
            0x15: self._parse_less_unsigned,
            0x16: self._parse_sign_extend,
            0x17: self._parse_ref8,
            0x18: self._parse_ref16,
            0x19: self._parse_ref32,
            0x1a: self._parse_ref64,
            0x20: self._parse_if_goto,
            0x21: self._parse_goto,
            0x2a: self._parse_zero_extend,
            0x2b: self._parse_swap,
            0x2c: self._parse_getv,
            0x22: self._parse_const8,
            0x23: self._parse_const16,
            0x24: self._parse_const32,
            0x25: self._parse_const64,
            0x26: self._parse_reg,
            0x27: self._parse_end,
            0x80: self._parse_xref8,
            0x81: self._parse_xref16,
            0x82: self._parse_xref32,
            0x83: self._parse_xref64,
        }

    def _get(self, n=1):
        value = 0

        for i in range(n):
            if self._ax_ptr >= len(self._ax):
                raise InvalidAxError('Unexpected end of AX')

            value <<= 8
            value |= self._ax[self._ax_ptr]
            self._ax_ptr += 1

        return value

    def _parse_add(self, ax_ptr):
        return AddOp(ax_ptr)

    def _parse_sub(self, ax_ptr):
        return SubOp(ax_ptr)

    def _parse_mul(self, ax_ptr):
        return MulOp(ax_ptr)

    def _parse_rem_signed(self, ax_ptr):
        return RemSignedOp(ax_ptr)

    def _parse_rem_unsigned(self, ax_ptr):
        return RemUnsignedOp(ax_ptr)

    def _parse_left_shift(self, ax_ptr):
        return LeftShiftOp(ax_ptr)

    def _parse_right_signed_shift(self, ax_ptr):
        return RightSignedShiftOp(ax_ptr)

    def _parse_right_unsigned_shift(self, ax_ptr):
        return RightUnsignedShiftOp(ax_ptr)

    def _parse_log_not(self, ax_ptr):
        return LogNotOp(ax_ptr)

    def _parse_and(self, ax_ptr):
        return AndOp(ax_ptr)

    def _parse_or(self, ax_ptr):
        return OrOp(ax_ptr)

    def _parse_xor(self, ax_ptr):
        return XorOp(ax_ptr)

    def _parse_equal(self, ax_ptr):
        return EqualOp(ax_ptr)

    def _parse_less_signed(self, ax_ptr):
        return LessSignedOp(ax_ptr)

    def _parse_less_unsigned(self, ax_ptr):
        return LessUnsignedOp(ax_ptr)

    def _parse_sign_extend(self, ax_ptr):
        return SignExtendOp(ax_ptr, self._get())

    def _parse_zero_extend(self, ax_ptr):
        return ZeroExtendOp(ax_ptr, self._get())

    def _parse_if_goto(self, ax_ptr):
        return IfGotoOp(ax_ptr, self._get(2))

    def _parse_goto(self, ax_ptr):
        return GotoOp(ax_ptr, self._get(2))

    def _parse_ref8(self, ax_ptr):
        return Ref8Op(ax_ptr)

    def _parse_ref16(self, ax_ptr):
        return Ref16Op(ax_ptr)

    def _parse_ref32(self, ax_ptr):
        return Ref32Op(ax_ptr)

    def _parse_ref64(self, ax_ptr):
        return Ref64Op(ax_ptr)

    def _parse_swap(self, ax_ptr):
        return SwapOp(ax_ptr)

    def _parse_getv(self, ax_ptr):
        tsv = self._get(2)
        return GetVOp(ax_ptr, tsv)

    def _parse_const8(self, ax_ptr):
        return Const8Op(ax_ptr, self._get())

    def _parse_const16(self, ax_ptr):
        return Const16Op(ax_ptr, self._get(2))

    def _parse_const32(self, ax_ptr):
        return Const32Op(ax_ptr, self._get(4))

    def _parse_const64(self, ax_ptr):
        return Const64Op(ax_ptr, self._get(8))

    def _parse_reg(self, ax_ptr):
        return RegOp(ax_ptr, self._get(2))

    def _parse_end(self, ax_ptr):
        return EndOp(ax_ptr)

    def _parse_xref8(self, ax_ptr):
        return Xref8Op(ax_ptr, self._get())

    def _parse_xref16(self, ax_ptr):
        return Xref16Op(ax_ptr, self._get())

    def _parse_xref32(self, ax_ptr):
        return Xref32Op(ax_ptr, self._get())

    def _parse_xref64(self, ax_ptr):
        return Xref64Op(ax_ptr, self._get())

    def parse(self, ax_str, lvalue=False):
        ops = []
        self._ax = binascii.unhexlify(ax_str)
        self._ax_ptr = 0

        while self._ax_ptr < len(self._ax):
            this_ax_ptr = self._ax_ptr
            op = self._get()

            if op not in self._handlers:
                fmt = 'Operator {} invalid (or not implemented).'
                raise InvalidAxError(fmt.format(hex(op)), self._ax_ptr - 1)

            p = self._handlers[op](this_ax_ptr)
            ops.append(p)

        return ops


def print_error(ax_str, exc):
    print('  {}'.format(ax_str))
    print('  {}^'.format('  ' * exc.offset))


def print_nicely(ops):
    for op in ops:
        print(' {:4}: {}'.format(op.offset, op))


def main(ax_str):
    ax_parser = AxDisas()
    try:
        result = ax_parser.parse(ax_str)
        print_nicely(result)
    except InvalidAxError as e:
        print('Error:', e)
        print()
        print_error(ax_str, e)
        print()
        raise


def cli_main():
    if len(sys.argv) != 2:
        print("Exactly one argument expected.")
        sys.exit(1)

    main(sys.argv[1])


if __name__ == '__main__':
    cli_main()
