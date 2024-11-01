# 3

> ###
> ### Welcome to /challenge/embryogdb_level3!
> ###
>
> GDB is a very powerful dynamic analysis tool which you can use in order to understand the state of a program throughout
> its execution. You will become familiar with some of gdb's capabilities in this module.
>
> You can examine the contents of memory using the `x/<n><u><f> <address>` parameterized command. 
>
> In this format

第一个，数字，查看的个数

第二个，b,h,w,g查看几个字节

第三个，格式，这些字节用什么格式解析，d，十进制，x，十六进制，s，字符串，i指令

> `<u>` is the unit size to display, 
>
> `<f>` is the format to display it in, and 
>
> `<n>` is the number of elements to display. 
>
> Valid unit sizes are `b` (1 byte), `h` (2 bytes), `w` (4 bytes), and `g` (8 bytes). 
>
> Valid formats are `d` (decimal), `x` (hexadecimal), `s` (string) and `i` (instruction).
>
> The address can be specified using a register name, symbol name, or
> absolute address. Additionally, you can supply mathematical expressions when specifying the address.
>
> For example, `x/8i $rip` will print the next 8 instructions from the current instruction pointer. `x/16i main` will
> print the first 16 instructions of main. You can also use `disassemble main`, or `disas main` for short, to print all of
> the instructions of main. Alternatively, `x/16gx $rsp` will print the first 16 values on the stack. `x/gx $rbp-0x32`
> will print the local variable stored there on the stack.
>
> You will probably want to view your instructions using the CORRECT assembly syntax. You can do that with the command
> `set disassembly-flavor intel`.
>
> In order to solve this level, you must figure out the random value on the stack (the value read in from `/dev/urandom`).
> Think about what the arguments to the read system call are.



# 4

> ###
> ### Welcome to /challenge/embryogdb_level4!
> ###
>
> GDB is a very powerful dynamic analysis tool which you can use in order to understand the state of a program throughout
> its execution. You will become familiar with some of gdb's capabilities in this module.
>
> A critical part of dynamic analysis is getting your program to the state you are interested in analyzing. So far, these
> challenges have automatically set breakpoints for you to pause execution at states you may be interested in analyzing.
> It is important to be able to do this yourself.
>
> There are a number of ways to move forward in the program's execution. You can use the `stepi <n>` command, or `si <n>`
> for short, in order to step forward one instruction. You can use the `nexti <n>` command, or `ni <n>` for short, in
> order to step forward one instruction, while stepping over any function calls. The `<n>` parameter is optional, but
> allows you to perform multiple steps at once. You can use the `finish` command in order to finish the currently
> executing function. You can use the `break *<address>` parameterized command in order to set a breakpoint at the
> specified-address. You have already used the `continue` command, which will continue execution until the program hits a
> breakpoint.
>
> While stepping through a program, you may find it useful to have some values displayed to you at all times. There are
> multiple ways to do this. The simplest way is to use the `display/<n><u><f>` parameterized command, which follows
> exactly the same format as the `x/<n><u><f>` parameterized command. For example, `display/8i $rip` will always show you
> the next 8 instructions. On the other hand, `display/4gx $rsp` will always show you the first 4 values on the stack.
> Another option is to use the `layout regs` command. This will put gdb into its TUI mode and show you the contents of all
> of the registers, as well as nearby instructions.
>
> In order to solve this level, you must figure out a series of random values which will be placed on the stack. You are
> highly encouraged to try using combinations of `stepi`, `nexti`, `break`, `continue`, and `finish` to make sure you have
> a good internal understanding of these commands. The commands are all absolutely critical to navigating a program's
> execution.



# 5



# 6



# 7



# 8



