from ast import *
txt = open('boxast.txt').read().strip()
exec('tree='+txt[1:-1])
src=unparse(fix_missing_locations(tree))
open('src.py','w').write(src)