#!/usr/bin/env bash

function do_test {
	python3 gdb-ax.py $1
	echo
}

# 21 + 21 == 42
do_test 22152215021620222a1327

# 21 - 21 == 0
do_test 2215221503162022001327

# 21 * 2 == 42
do_test 22152202041620222a1327

# 21 << 1 == 42
do_test 22152201091620222a1327

# 42 >> 1 == 21
do_test 222a22010a162022151327

# -(21 << 1) == -42
do_test 22002215220109162003162022d616081327

# -42 >> 1 == -21
do_test 22d6160822010a162022eb16081327

# (0xabababab & 0x0000ffff) == 0xabab
do_test 2500000000abababab240000ffff2a200f240000abab2a201327

# (0xabababab | 0x0000ffff) == 0xababffff
do_test 2500000000abababab240000ffff2a20102500000000ababffff1327

# (0xaaaaaaaa ^ 0x55555555) == 0xffffffff
do_test 2500000000aaaaaaaa24555555552a20112500000000ffffffff1327

# 21 < 42
do_test 2215222a1427

# 42 <= 42
do_test 222a222a2b140e27

# 42 >= 42
do_test 222a222a140e27

# 42 > 21
do_test 222a22152b1427

# $rip == *set_point
do_test 2600102a40240040067b1327