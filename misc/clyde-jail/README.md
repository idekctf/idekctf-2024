# clyde-jail
**Category:** Misc
**Difficulty:** Hard
**Author:** icesfont

## Description
![basic_calculator(input=f = resolve("constructor('test')")._compile({},{}); p = f(null, cos); p())](https://locker.kotoha.moe/-7dHvMPe7ww/yes.png)

**Hints (24hr mark):**

the intended solution uses the prototype pollution in order to access arbitrary properties of any object, in particular `({}).constructor`; it then uses this to get access to the global object and win. (getting access to the function constructor, `Function`, does not immediately win given the `--disallow-code-generation-from-strings` option.)

node internals are out of scope for the intended solution.

specific hints for the intended solution (there may be other ways to achieve the above):

- have you seen this? https://github.com/josdejong/mathjs/blob/14acdad7e8e2f9e2dbb6fc26ab1eef569e02138d/HISTORY.md?plain=1#L1666-L1668
- how is accessing object properties implemented?
- `Error.prepareStackTrace`
 
