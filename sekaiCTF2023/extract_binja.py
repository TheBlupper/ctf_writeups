import re
import json
from struct import pack, unpack
from pathlib import Path
import numpy as np
from binaryninja import *

# Load the coefficient matrix
A = np.array(
    unpack('d'*256, bv.read(
        bv.get_symbols_by_name('A')[0].address,
        256*8))
).astype(np.int64).reshape(16, 16)

targets = []
main = bv.get_functions_by_name('main')[0]

# Extract blocks from HLIL
hlil = str(main.hlil)
for i in range(0, 8, 2):
    block = b''
    for j in range(2):
        n = int(next(re.finditer(f'(0x[0-9a-f]+) \\^ out\\[{i+j}\\]', hlil)).group(1), 0)
        block += pack('<Q', n)
    # We subtract 33 here already because we can
    targets.append([b-33 for b in block])

out = {
    'A': A.tolist(),
    'targets': targets
}
with open(Path(bv.file.filename).parent/'extracted.json', 'w') as f:
    json.dump(out, f)