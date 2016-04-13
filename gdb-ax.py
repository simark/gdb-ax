#!/usr/bin/env python3

import binascii
import sys


class InvalidAxError(Exception):
    pass


class BaseOp:
    pass


class AddOp(BaseOp):

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
        return 'AddOp(op_a={}, op_b={})'.format(self.op_a,
                                                self.op_b)


class EqualOp(BaseOp):

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
        return 'EqualOp(op_a={}, op_b={})'.format(self.op_a,
                                                  self.op_b)


class SignExtendOp(BaseOp):

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
        return 'SignExtendOp(value={}, n_bits={})'.format(self.value,
                                                          self.n_bits)


class Const8Op(BaseOp):

    def __init__(self, operand):
        self._operand = operand

    @property
    def operand(self):
        return self._operand

    def __repr__(self):
        return 'Const8Op(operand={} {})'.format(self.operand,
                                                hex(self.operand))


class AxParser:

    def __init__(self):
        self._handlers = {
            0x02: self._parse_add,
            0x13: self._parse_equal,
            0x16: self._parse_sign_extend,
            0x22: self._parse_const8,
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

    def _parse_add(self):
        op_b = self._pop()
        op_a = self._pop()

        self._push(AddOp(op_a, op_b))

    def _parse_equal(self):
        op_b = self._pop()
        op_a = self._pop()

        self._push(EqualOp(op_a, op_b))

    def _parse_sign_extend(self):
        n_bits = self._get()
        val = self._pop()

        self._push(SignExtendOp(val, n_bits))

    def _parse_const8(self):
        self._push(Const8Op(self._get()))

    def _parse_end(self):
        self._end_seen = 1
        pass

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
    # 22152215021620222a1327
    ax_parser = AxParser()
    stmts = ax_parser.parse(ax_str)
    print(stmts)

if __name__ == '__main__':
    main(sys.argv[1])
