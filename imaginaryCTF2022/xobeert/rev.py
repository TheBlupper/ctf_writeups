zero = lambda f: 0
one = lambda f: 1
emptylist = lambda f: []
add = lambda a: lambda b: a + b

@add
@one
class inc:
    pass
push = lambda item: lambda stack: [item] + stack
pop = lambda stack: stack[1:]
add = lambda stack: [stack[1] + stack[0]] + stack[2:]
sub = lambda stack: [stack[1] - stack[0]] + stack[2:]
pow = lambda stack: [stack[1] ** stack[0]] + stack[2:]
mul = lambda stack: [stack[1] * stack[0]] + stack[2:]
getbottom = lambda stack: stack[0]

@push
@zero
class push0:
    pass

@push
@inc
@zero
class push1:
    pass

@push
@getbottom
@add
@push1
@push1
@emptylist
class push2:
    pass

@push
@getbottom
@add
@push2
@push1
@emptylist
class push3:
    pass

@push
@getbottom
@mul
@push2
@push2
@emptylist
class reverse_xorkey:
    pass

@push
@getbottom
@add
@push2
@push3
@emptylist
class push5:
    pass

@push
@getbottom
@mul
@push2
@push3
@emptylist
class push6:
    pass

@push
@getbottom
@add
@push2
@push5
@emptylist
class push7:
    pass

@push
@getbottom
@pow
@push3
@push2
@emptylist
class push8:
    pass

@push
@getbottom
@add
@push2
@push8
@emptylist
class push10:
    pass

@push
@getbottom
@add
@reverse_xorkey
@push7
@emptylist
class push11:
    pass

@push
@getbottom
@add
@push2
@push11
@emptylist
class push13:
    pass

@push
@getbottom
@mul
@push5
@push3
@emptylist
class push15:
    pass

@push
@getbottom
@pow
@reverse_xorkey
@push2
@emptylist
class push16:
    pass

@push
@getbottom
@add
@push1
@pow
@reverse_xorkey
@push2
@emptylist
class push17:
    pass

@push
@getbottom
@mul
@push5
@reverse_xorkey
@emptylist
class push20:
    pass

@push
@getbottom
@mul
@push3
@push7
@emptylist
class push21:
    pass

@push
@getbottom
@mul
@push2
@push11
@emptylist
class push22:
    pass

@push
@getbottom
@add
@push2
@push21
@emptylist
class push23:
    pass

@push
@getbottom
@pow
@push5
@push2
@emptylist
class push32:
    pass

@push
@getbottom
@add
@push1
@pow
@push5
@push2
@emptylist
class push33:
    pass

@push
@getbottom
@add
@push1
@mul
@push5
@push8
@emptylist
class push41:
    pass

@push
@getbottom
@mul
@push5
@push10
@emptylist
class push50:
    pass

@push
@getbottom
@add
@push2
@mul
@push7
@push8
@emptylist
class push58:
    pass

@push
@getbottom
@add
@push3
@mul
@push7
@push8
@emptylist
class push59:
    pass

@push
@getbottom
@sub
@push1
@mul
@push16
@reverse_xorkey
@emptylist
class push63:
    pass

@push
@getbottom
@add
@push1
@mul
@push16
@reverse_xorkey
@emptylist
class push65:
    pass

@push
@getbottom
@add
@push3
@mul
@push16
@reverse_xorkey
@emptylist
class push67:
    pass

@push
@getbottom
@mul
@push10
@push7
@emptylist
class push70:
    pass

@push
@getbottom
@add
@push1
@mul
@push10
@push7
@emptylist
class push71:
    pass

@push
@getbottom
@add
@push7
@mul
@push16
@push5
@emptylist
class push87:
    pass

@push
@getbottom
@sub
@push2
@mul
@push3
@pow
@push5
@push2
@emptylist
class push94:
    pass

@push
@getbottom
@sub
@push1
@mul
@push3
@pow
@push5
@push2
@emptylist
class push95:
    pass

@push
@getbottom
@add
@push1
@mul
@push3
@pow
@push5
@push2
@emptylist
class push97:
    pass

@push
@getbottom
@mul
@push2
@pow
@push2
@push7
@emptylist
class push98:
    pass

@push
@getbottom
@sub
@push1
@mul
@push20
@push5
@emptylist
class push99:
    pass

@push
@getbottom
@mul
@push20
@push5
@emptylist
class push100:
    pass

@push
@getbottom
@add
@push1
@mul
@push5
@push20
@emptylist
class push101:
    pass

@push
@getbottom
@add
@push2
@mul
@push5
@push20
@emptylist
class push102:
    pass

@push
@getbottom
@add
@push3
@mul
@push5
@push20
@emptylist
class push103:
    pass

@push
@getbottom
@sub
@push1
@mul
@push5
@push21
@emptylist
class push104:
    pass

@push
@getbottom
@mul
@push5
@push21
@emptylist
class push105:
    pass

@push
@getbottom
@add
@push3
@mul
@push5
@push21
@emptylist
class push108:
    pass

@push
@getbottom
@add
@reverse_xorkey
@mul
@push5
@push21
@emptylist
class push109:
    pass

@push
@getbottom
@mul
@push5
@push22
@emptylist
class push110:
    pass

@push
@getbottom
@add
@push1
@mul
@push5
@push22
@emptylist
class push111:
    pass

@push
@getbottom
@add
@push3
@mul
@push5
@push22
@emptylist
class push113:
    pass

@push
@getbottom
@sub
@push1
@mul
@push5
@push23
@emptylist
class push114:
    pass

@push
@getbottom
@mul
@push5
@push23
@emptylist
class push115:
    pass

@push
@getbottom
@add
@push115
@push1
@emptylist
class push116:
    pass

@push
@getbottom
@add
@push115
@push3
@emptylist
class push118:
    pass

@push
@getbottom
@sub
@push1
@mul
@push11
@push11
@emptylist
class push120:
    pass

@push
@getbottom
@mul
@push11
@push11
@emptylist
class push121:
    pass

@push
@getbottom
@add
@push2
@mul
@push11
@push11
@emptylist
class push123:
    pass

@push
@getbottom
@add
@push1
@mul
@reverse_xorkey
@mul
@push3
@push11
@emptylist
class push133:
    pass

@push
@getbottom
@add
@push5
@mul
@reverse_xorkey
@mul
@push3
@push11
@emptylist
class push137:
    pass

@push
@getbottom
@sub
@mul
@push3
@push3
@mul
@push13
@push13
@emptylist
class push160:
    pass

@push
@getbottom
@mul
@push13
@push13
@emptylist
class push169:
    pass

@push
@getbottom
@mul
@push7
@mul
@push5
@push5
@emptylist
class push175:
    pass

@push
@getbottom
@add
@push1
@mul
@push16
@push11
@emptylist
class push177:
    pass

@push
@getbottom
@add
@push8
@mul
@push16
@push11
@emptylist
class push184:
    pass

@push
@getbottom
@mul
@push15
@push13
@emptylist
class push195:
    pass

@push
@getbottom
@add
@push10
@mul
@push15
@push13
@emptylist
class push205:
    pass

@push
@getbottom
@add
@push1
@mul
@mul
@push3
@push3
@mul
@push5
@push5
@emptylist
class push226:
    pass

@push
@getbottom
@sub
@push1
@mul
@push2
@pow
@push3
@push5
@emptylist
class push249:
    pass

@push
@getbottom
@mul
@push2
@pow
@push3
@push5
@emptylist
class push250:
    pass

@push
@getbottom
@add
@push1
@push250
@emptylist
class push251:
    pass

# Import sys
@__import__
@bytes.decode
@bytes
@push115
@push121
@push115
@emptylist
class sys:
    pass

@__import__
@bytes.decode
@bytes
@push116
@push97
@push110
@push100
@push111
@push109
@emptylist
class random:
    pass

@sys.__dict__.get
@bytes.decode
@bytes
@push101
@push120
@push105
@push116
@emptylist
class sys_exit:
    pass

@random.__dict__.get
@bytes.decode
@bytes
@push115
@push101
@push101
@push100
@emptylist
class random_seed:
    pass

@random.__dict__.get
@bytes.decode
@bytes
@push116
@push97
@push110
@push100
@push98
@push121
@push116
@push101
@push115
@emptylist
class random_randbytes:
    pass

@input
@bytes.decode
@bytes
@push102
@push108
@push97
@push103
@push63
@push32
@emptylist
class userinput:
    pass
wrapped_userinput = lambda _: userinput

@len
@wrapped_userinput
class inputlen:
    pass
wrapped_inputlen = lambda _: inputlen

@range
@wrapped_inputlen
class looprange:
    pass
xor_with_input = lambda x: lambda y: [x[i] ^ y[i] for i in looprange]

@xor_with_input
@str.encode
@wrapped_userinput
class xor_with_input:
    pass
wrap = lambda a: lambda _: a

@wrap
@bytes.decode
@bytes
@push87
@push116
@push111
@push110
@push103
@push33
@emptylist
class wrong:
    pass

@wrap
@bytes.decode
@bytes
@push67
@push111
@push116
@push116
@push101
@push99
@push116
@push32
@push58
@push41
@emptylist
class correct:
    pass

@wrap
@push133
@push175
@push1
@push177
@push184
@push118
@push50
@push169
@push251
@push100
@push205
@push160
@push17
@push226
@push65
@push67
@push5
@push59
@push137
@push59
@push71
@push70
@push249
@push195
@push121
@push95
@push94
@push250
@push123
@emptylist
class xorkey:
    pass

@emptylist.reverse
@xorkey
class reverse_xorkey:
    pass

@xorkey
class xorkey:
    pass
resultchecker = lambda f: lambda result: [wrong, correct][result == xorkey]

@resultchecker
class check_result:
    pass

@check_result
@xor_with_input
@random_randbytes
@wrapped_inputlen
@random_seed
@random_randbytes
@wrapped_inputlen
@random_seed
@bytes.decode
@bytes
@push100
@push101
@push98
@push100
@push98
@push101
@push101
@push102
@push95
@push111
@push116
@push95
@push115
@push116
@push104
@emptylist
class check_flag:
    pass

@print
@check_flag
class main:
    pass