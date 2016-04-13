#!/usr/bin/env python3

import binascii
import sys


class InvalidAxError(Exception):
    pass


class BaseOp:
    pass


class BinBaseOp:

    def __init__(self, op_a, op_b):
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


class EqualOp(BinBaseOp):
    pass


class ExtendBaseOp(BaseOp):

    def __init__(self, value, n_bits):
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


class ConstBaseOp(BaseOp):

    def __init__(self, operand):
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


class AxParser:

    def __init__(self):
        self._handlers = {
            0x02: self._parse_add,
            0x03: self._parse_sub,
            0x04: self._parse_mul,
            0x09: self._parse_left_shift,
            0x0a: self._parse_right_signed_shift,
            0x0b: self._parse_right_unsigned_shift,
            0x13: self._parse_equal,
            0x16: self._parse_sign_extend,
            0x2a: self._parse_zero_extend,
            0x22: self._parse_const8,
            0x23: self._parse_const16,
            0x24: self._parse_const32,
            0x25: self._parse_const64,
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

    def _parse_binop(self, obj_cls):
        op_b = self._pop()
        op_a = self._pop()

        self._push(obj_cls(op_a, op_b))

    def _parse_add(self):
        self._parse_binop(AddOp)

    def _parse_sub(self):
        self._parse_binop(SubOp)

    def _parse_mul(self):
        self._parse_binop(MulOp)

    def _parse_left_shift(self):
        self._parse_binop(LeftShiftOp)

    def _parse_right_signed_shift(self):
        self._parse_binop(RightSignedShiftOp)

    def _parse_right_unsigned_shift(self):
        self._parse_binop(RightUnsignedShiftOp)

    def _parse_equal(self):
        self._parse_binop(EqualOp)

    def _parse_extend(self, cls_obj):
        n_bits = self._get()
        val = self._pop()

        self._push(cls_obj(val, n_bits))

    def _parse_sign_extend(self):
        self._parse_extend(SignExtendOp)

    def _parse_zero_extend(self):
        self._parse_extend(ZeroExtendOp)

    def _parse_const(self, cls_obj, n):
        val = 0
        for i in range(n):
            val <<= 8
            val |= self._get()

        self._push(cls_obj(val))

    def _parse_const8(self):
        self._parse_const(Const8Op, 1)

    def _parse_const16(self):
        self._parse_const(Const16Op, 2)

    def _parse_const32(self):
        self._parse_const(Const32Op, 4)

    def _parse_const64(self):
        self._parse_const(Const64Op, 8)

    def _parse_end(self):
        self._end_seen = 1

    def parse(self, ax_str, lvalue=False):
        self._stack = []
        self._ax = binascii.unhexlify(ax_str)
        self._ax_ptr = 0
        self._end_seen = 0

        while not self._end_seen:
            op = self._get()

            if op not in self._handlers:
                raise NotImplementedError(
                    'Operator {} not implemented or invalid'.format(hex(op)))

            self._handlers[op]()

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
