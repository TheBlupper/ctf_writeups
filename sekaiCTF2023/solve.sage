import json

def rc(a, b):
    return ((((a & 0xf) << b) | ((a & 0xf) >> (4 - b))) & 0xf) | (a & 0xf0)

with open('./extracted.json', 'rb') as f:
    out = json.load(f)

R = Zmod(94)
targets = out['targets']
A = matrix(R, out['A'])
for target in targets:
    # TYL: this is valid sage syntax
    v = A \ vector(R, target)
    print(end=bytes([rc(int(b), 1)+33 for b in v]).decode())
# -> SEKAI{1_I_i_|_H0oOo@p3eEe_Y0Uu\_/Didn't_BruT3F0rCe_GuYy5}XXXXXXX