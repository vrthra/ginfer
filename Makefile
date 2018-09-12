subject=./subjects/expr.lr1
arg='1+1'
python=/usr/bin/pypy

run:
	$(python) $(debug) ./src/main.py $(subject) $(arg)

