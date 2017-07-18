# Stack Tracer

A tool for RTEMS basic stack trace information extraction

## What are the dependencies?

The Stack Tracer is written in Python (>= 2.6), and that's your only dependency.

## How do I use this script?

You'll need:

- A memory dump from the binary you want to debug
- The stack trace

### Obtaining the memory dump

Use `objdump` to obtain the file. If cross-compiling, you may need to look around
for the right binary, eg: `powerpc-rtems4.10-objdump`. Then run it like this,
for example:

    objdump -g -S --line-numbers --demangle <binary-file> > memmap

`-g` will show debugging information, while `-S` intermixes source code with
the disassembly. `--line-numbers` will make it easier to find the code in the
source files. Finally, use `--demangle` for getting human-readable names from
C++ objects.

### Stack trace format

The typical exception dump from RTEMS contains information about the type
of exception, registers, and a stack trace. This last part is the only one
of interest for us:

    Stack Trace:
     IP: 0x0012EFC8, LR: 0x0011D450
    --^ 0x0001A48C--^ 0x00018F9C--^ 0x000EC690--^ 0x000F0E64--^ 0x000EE044
    --^ 0x000E0AB8--^ 0x000E7094--^ 0x00136048--^ 0x00135F6C
    Suspending faulting task (0x0A010012)

The script will capture the information between the first line starting with
`Stack Trace` and the one starting with `Suspending`. The rest of the file is
ignored, meaning that you can remove the register information, add comments,
or whatever.

### Usage

Finally, to use the `stack-tracer` script:

    stack-tracer.py <path-to-memmap> <path-to-stack-trace>
