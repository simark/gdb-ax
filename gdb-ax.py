#!/usr/bin/env python3

import binascii
import sys


class InvalidAxError(Exception):
    pass


class BaseOp:

    def __init__(self, ax_ptr):
        self._ax_ptr = ax_ptr

    @property
    def ax_ptr(self):
        return self._ax_ptr


class UnaryBaseOp(BaseOp):

    def __init__(self, ax_ptr, op):
        super().__init__(ax_ptr)
        self._op = op

    @property
    def op(self):
        return self._op

    def __repr__(self):
        cls_name = type(self).__name__

        return '{}(op={})'.format(cls_name,
                                  self.op)


class BinBaseOp(BaseOp):

    def __init__(self, ax_ptr, op_a, op_b):
        super().__init__(ax_ptr)
        self._op_a = op_a
        self._op_b = op_b

    @property
    def op_a(self):
        return self._op_a

    @property
    def op_b(self):
        return self._op_b

    def __repr__(self):
        cls_name = type(self).__name__

        return '{}(op_a={}, op_b={})'.format(cls_name,
                                             self.op_a,
                                             self.op_b)


class AddOp(BinBaseOp):
    pass


class SubOp(BinBaseOp):
    pass


class MulOp(BinBaseOp):
    pass


class LeftShiftOp(BinBaseOp):
    pass


class RightSignedShiftOp(BinBaseOp):
    pass


class RightUnsignedShiftOp(BinBaseOp):
    pass


class LogNotOp(UnaryBaseOp):
    pass


class AndOp(BinBaseOp):
    pass


class OrOp(BinBaseOp):
    pass


class XorOp(BinBaseOp):
    pass


class EqualOp(BinBaseOp):
    pass


class LessSignedOp(BinBaseOp):
    pass


class LessUnsignedOp(BinBaseOp):
    pass


class ExtendBaseOp(BaseOp):

    def __init__(self, ax_ptr, value, n_bits):
        super().__init__(ax_ptr)
        self._value = value
        self._n_bits = n_bits

    @property
    def value(self):
        return self._value

    @property
    def n_bits(self):
        return self._n_bits

    def __repr__(self):
        cls_name = type(self).__name__
        return '{}(value={}, n_bits={})'.format(cls_name,
                                                self.value,
                                                self.n_bits)


class SignExtendOp(ExtendBaseOp):
    pass


class ZeroExtendOp(ExtendBaseOp):
    pass


class RefOp(BaseOp):

    def __init__(self, ax_ptr, addr):
        super().__init__(ax_ptr)
        self._addr = addr

    @property
    def addr(self):
        return self._addr

    def __repr__(self):
        return 'RefOp(addr={})'.format(hex(self.addr))


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


class AxParser:

    def __init__(self):
        self._handlers = {
            0x02: self._parse_add,
            0x03: self._parse_sub,
            0x04: self._parse_mul,
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
            0x2a: self._parse_zero_extend,
            0x2b: self._parse_swap,
            0x22: self._parse_const8,
            0x23: self._parse_const16,
            0x24: self._parse_const32,
            0x25: self._parse_const64,
            0x26: self._parse_reg,
            0x27: self._parse_end,
        }

    def _get(self):
        if self._ax_ptr >= len(self._ax):
            raise InvalidAxError('Unexpected end of AX')

        value = self._ax[self._ax_ptr]
        self._ax_ptr += 1

        return value

    def _push(self, op_obj):
        print('Pushing {}'.format(op_obj))
        self._stack.append(op_obj)

    def _pop(self):
        try:
            return self._stack.pop()
        except IndexError as e:
            raise InvalidAxError('Trying to pop an empty stack.') from e

    def _parse_binop(self, obj_cls, ax_ptr):
        op_b = self._pop()
        op_a = self._pop()

        self._push(obj_cls(ax_ptr, op_a, op_b))

    def _parse_add(self, ax_ptr):
        self._parse_binop(AddOp, ax_ptr)

    def _parse_sub(self, ax_ptr):
        self._parse_binop(SubOp, ax_ptr)

    def _parse_mul(self, ax_ptr):
        self._parse_binop(MulOp, ax_ptr)

    def _parse_left_shift(self, ax_ptr):
        self._parse_binop(LeftShiftOp, ax_ptr)

    def _parse_right_signed_shift(self, ax_ptr):
        self._parse_binop(RightSignedShiftOp, ax_ptr)

    def _parse_right_unsigned_shift(self, ax_ptr):
        self._parse_binop(RightUnsignedShiftOp, ax_ptr)

    def _parse_log_not(self, ax_ptr):
        op = self._pop()

        self._push(LogNotOp(ax_ptr, op))

    def _parse_and(self, ax_ptr):
        self._parse_binop(AndOp, ax_ptr)

    def _parse_or(self, ax_ptr):
        self._parse_binop(OrOp, ax_ptr)

    def _parse_xor(self, ax_ptr):
        self._parse_binop(XorOp, ax_ptr)

    def _parse_equal(self, ax_ptr):
        self._parse_binop(EqualOp, ax_ptr)

    def _parse_less_signed(self, ax_ptr):
        self._parse_binop(LessSignedOp, ax_ptr)

    def _parse_less_unsigned(self, ax_ptr):
        self._parse_binop(LessUnsignedOp, ax_ptr)

    def _parse_extend(self, cls_obj, ax_ptr):
        n_bits = self._get()
        val = self._pop()

        self._push(cls_obj(ax_ptr, val, n_bits))

    def _parse_sign_extend(self, ax_ptr):
        self._parse_extend(SignExtendOp, ax_ptr)

    def _parse_zero_extend(self, ax_ptr):
        self._parse_extend(ZeroExtendOp, ax_ptr)

    def _parse_ref(self, ax_ptr, n):
        addr = 0

        for i in range(n):
            addr = addr << 8 | self._get()

        self._push(RefOp(ax_ptr, addr))

    def _parse_ref8(self, ax_ptr):
        self._parse_ref(ax_ptr, 1)

    def _parse_ref16(self, ax_ptr):
        self._parse_ref(ax_ptr, 2)

    def _parse_ref32(self, ax_ptr):
        self._parse_ref(ax_ptr, 4)

    def _parse_ref64(self, ax_ptr):
        self._parse_ref(ax_ptr, 8)

    def _parse_swap(self, ax_ptr):
        op_b = self._pop()
        op_a = self._pop()

        self._push(op_b)
        self._push(op_a)

    def _parse_const(self, cls_obj, ax_ptr, n):
        val = 0
        for i in range(n):
            val <<= 8
            val |= self._get()

        self._push(cls_obj(ax_ptr, val))

    def _parse_const8(self, ax_ptr):
        self._parse_const(Const8Op, ax_ptr, 1)

    def _parse_const16(self, ax_ptr):
        self._parse_const(Const16Op, ax_ptr, 2)

    def _parse_const32(self, ax_ptr):
        self._parse_const(Const32Op, ax_ptr, 4)

    def _parse_const64(self, ax_ptr):
        self._parse_const(Const64Op, ax_ptr,  8)

    def _parse_reg(self, ax_ptr):
        regh = self._get()
        regl = self._get()

        reg = regh << 8 | regl

        self._push(RegOp(ax_ptr, reg))

    def _parse_end(self, ax_ptr):
        self._end_seen = 1

    def parse(self, ax_str, lvalue=False):
        self._stack = []
        self._ax = binascii.unhexlify(ax_str)
        self._ax_ptr = 0
        self._end_seen = 0

        while not self._end_seen:
            this_ax_ptr = self._ax_ptr
            op = self._get()

            if op not in self._handlers:
                raise NotImplementedError(
                    'Operator {} not implemented or invalid'.format(hex(op)))

            self._handlers[op](this_ax_ptr)

        if lvalue:
            if len(self._stack) != 2:
                raise InvalidAxError(
                    'End reached, lvalue expected, stack size != 2')

            return tuple(self._stack)
        else:
            if len(self._stack) != 1:
                raise InvalidAxError(
                    'End reached, rvalue expected, stack size != 1')

            return self._stack[0]


def main(ax_str):
    ax_parser = AxParser()
    result = ax_parser.parse(ax_str)
    print(result)

if __name__ == '__main__':
    main(sys.argv[1])
