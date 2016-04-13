function do_test {
	python3 gdb-ax.py $1
	echo
}

# 21 + 21 == 42
do_test 22152215021620222a1327

# 21 - 21 == 0
do_test 2215221503162022001327
