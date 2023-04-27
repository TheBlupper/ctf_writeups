# Paste this in the Python console in Binary Ninja
# The functions *should* be in the right order
import json
rows = []
for func in bv.functions:
    if not func.name.startswith('func'): continue
    row = []
    print(func.name)
    # They are so big they might get skipped due to 
    # time restrictions
    if func.analysis_skipped:
        func.analysis_skip_override = FunctionAnalysisSkipOverride.NeverSkipFunctionAnalysis
    for line in map(str,func.hlil.root.lines):
        if '=' not in line: continue
        val = line.split('=')[1] # Get assignment value
        # There is an assignment to a temp
        # variable towards the end, we ignore that
        if not 'check' in val: continue
        # + 0 gets optimized away in the decompilation
        if not ('+' in val or '-' in val):
            row.append(0)
            continue
        # Sometimes it's  - - 1337 which wouldn't work with
        # int(), hopefully they didn't plant a trap :P
        row.append(eval(val.split(']')[1]))
    rows.append(row)
json.dump(rows, open('coeffs.json','w'))
