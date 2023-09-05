from binaryninja import *
from capstone import *
from capstone.x86 import *

x86_64 = Architecture['x86_64']

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def from_op(op: X86Op, il: LowLevelILFunction, instr=None, dont_load=False) -> LowLevelILExpr:
    if op.type == X86_OP_REG:
        return il.reg(op.size, md.reg_name(op.reg))
    elif op.type == X86_OP_IMM:
        return il.const(op.size, op.imm)
    elif op.type == X86_OP_MEM:
        m = il.const(8, 0)
        if op.mem.disp != 0:
            m = il.add(8, m, il.const(8, op.mem.disp))
        if op.mem.base != 0:
            if op.mem.base == X86_REG_RIP and instr is not None:
                m = il.add(8, m, il.const(8, il.current_address + instr.size))
            else:
                m = il.add(8, m, il.reg(8, md.reg_name(op.mem.base)))
        if op.mem.index != 0:
            m = il.add(8, m, il.mult(8,
                    il.reg(8, md.reg_name(op.mem.index)),
                    il.const(8, op.mem.scale)))
        if not dont_load:
            m = il.load(op.size, m)
        return m
    else:
        raise ValueError('Unknown operand type: {}'.format(op.type))


class Patch(ArchitectureHook):
    def get_instruction_low_level_il(self, data: bytes, addr: int, il: LowLevelILFunction) -> int | None:
        instr = next(md.disasm(data, addr))
        length = instr.size

        if il.source_function.name == 'main': print(instr)
        if instr.mnemonic == 'and' and \
        instr.operands[0].type == X86_OP_REG and \
        instr.operands[0].reg == X86_REG_RSP:
            il.nop()
            return length
        
        if instr.mnemonic in ['vbroadcastsd']:
            # We keep as intrinsic but replace anyway since Binja's disassembly is wrong
            o_il = LowLevelILFunction(x86_64)
            super().get_instruction_low_level_il(data, addr, o_il)
            intrinsic = o_il[0].intrinsic.name
            il.append(il.intrinsic([md.reg_name(instr.operands[0].reg)], intrinsic, [from_op(instr.operands[1], il, instr)]))
            return length

        movs = ['vmovsd', 'vmovapd', 'vmovss', 'vmovdqa']
        if il.source_function.name == 'rc': movs += ['vpbroadcastb']
        if instr.mnemonic in movs:
            sz = instr.operands[0].size
            if instr.operands[0].type == X86_OP_MEM:
                il.append(il.store(sz,
                    from_op(instr.operands[0], il, instr, True),
                    from_op(instr.operands[-1], il, instr)))
            elif instr.operands[0].type == X86_OP_REG:
                il.append(il.set_reg(sz,
                    md.reg_name(instr.operands[0].reg),
                    from_op(instr.operands[-1], il, instr)))
            else:
                raise ValueError(f'Unknown operand type: {instr.operands[0].type}')
            return length
        
        if instr.mnemonic in ['vpsrld', 'vpslld']:
            assert all(op.type == X86_OP_REG for op in instr.operands)
            operation = [il.shift_left, il.logical_shift_right][instr.mnemonic == 'vpsrld']
            sz = instr.operands[0].size
            il.append(il.set_reg(sz,
                md.reg_name(instr.operands[0].reg),
                operation(sz,
                    from_op(instr.operands[1], il, instr),
                    from_op(instr.operands[2], il, instr))
            ))
            return length
        
        if instr.mnemonic in ['vxorpd', 'vxorps']:
            assert instr.operands[0].type == X86_OP_REG
            sz = instr.operands[0].size
            src = il.xor_expr(sz,
                from_op(instr.operands[0], il, instr),
                from_op(instr.operands[1], il, instr))
            il.append(il.set_reg(sz, md.reg_name(instr.operands[0].reg), src))
            return length
        
        # WARNING: very bad and naughty, but it looks so good decompiled ;-;
        if instr.mnemonic in ['vmulpd', 'vaddpd']:
            operation = [il.mult, il.add][instr.mnemonic == 'vaddpd']

            sz = instr.operands[0].size
            il.append(il.set_reg(sz, md.reg_name(instr.operands[0].reg),
                operation(
                    sz,
                    from_op(instr.operands[1], il, instr),
                    from_op(instr.operands[2], il, instr)))
            )
            return length
        
        if instr.mnemonic in ['vcvtusi2ss']:
            sz = instr.operands[0].size
            src_sz = instr.operands[2].size
            il.append(il.set_reg(sz, md.reg_name(instr.operands[0].reg),
                il.float_convert(src_sz, from_op(instr.operands[2], il, instr)))
            )
            return length
        
        if instr.mnemonic in ['vcvttss2usi', 'vcvttsd2usi']:
            sz = instr.operands[0].size
            src_sz = instr.operands[1].size
            il.append(il.set_reg(sz, md.reg_name(instr.operands[0].reg),
                il.float_trunc(src_sz, from_op(instr.operands[1], il, instr)))
            )
            return length
        

        return super().get_instruction_low_level_il(data, addr, il)

Patch(x86_64).register()