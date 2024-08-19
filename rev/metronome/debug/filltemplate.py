with open('metronome-template.c', 'r') as f:
    prog = f.read()

with open('params.txt', 'r') as f:
    params = f.readlines()

prog = prog.replace('{n}', params[0])
prog = prog.replace('{edg}', params[1])
prog = prog.replace('{bnd}', params[2])

with open('metronome.c', 'w') as f:
    f.write(prog)
