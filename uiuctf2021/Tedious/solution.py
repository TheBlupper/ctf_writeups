import angr

base_addr = 0x00100000
find_addr = 0x001019d1
avoid_addr = 0x001019a9

proj = angr.Project('./challenge', main_opts= {'base_addr' : base_addr})

simgr = proj.factory.simulation_manager()
simgr.explore(find=find_addr, avoid=avoid_addr)

STDIN_FD = 0 # 0 is the file descriptor of STDIN
if len(simgr.found) > 0:
    for found in simgr.found:
        print(f'Found flag: ' + found.posix.dumps(STDIN_FD).decode())
else:
    print('Could not find flag :(')
