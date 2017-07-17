#!/usr/bin/env python

from __future__ import print_function

import os
import re
import sys
from collections import namedtuple

Assembly = namedtuple('Assembly', 'address text')
Trace = namedtuple('Trace', 'exception_address stack')

COLORS = {
    'green': '32',
    'bright_green': '32;1',
    'yellow': '33',
    'bright_yellow': '33;1',
}

def colorize(text, color):
    return "\x1b[{0}m{1}\x1b[0m".format(COLORS[color], text)

class CodeBlock(object):
    def __init__(self):
        self.text = []
        self.code = []

    def __contains__(self, address):
        return any(c.address == address for c in self.code)

    def print(self):
        for t in self.text:
            print("    {0}".format(t))
        for c in self.code:
            print("    {0:08x}  {1}".format(c.address, c.text))

class FunctionDisassembly(object):
    def __init__(self, name):
        self.name = name
        self.first = None
        self.last = None
        self.lines = []

    def __contains__(self, address):
        return self.first <= address <= self.last

    def update(self):
        if not self.lines:
            raise RuntimeError("Updating an empty FunctionDisassembly!")
        try:
            self.first = self.lines[0].code[0].address
            self.last = self.lines[-1].code[-1].address
        except IndexError:
            raise RuntimeError("FunctionDisassembly object {} seems to be fucked up".format(self.name))

    def add_assembly(self, address, code):
        self.lines[-1].code.append(Assembly(address, code))

    def add_text(self, line):
        try:
            path, line_no = line.split(':')
            self.lines[-1].text.append("{}:{}".format(os.path.abspath(path), int(line_no)))
        except ValueError:
            self.lines[-1].text.append(line)

    def new_block(self):
        self.lines.append(CodeBlock())

    def print_context_for(self, address):
        for line in self.lines:
            if address in line:
                line.print()
                break
        else:
            raise RuntimeError("The address was not here!")

class RangeTreeNode(object):
    def __init__(self, left, right):
        self.start_address = left[0].first
        self.middle_address = right[0].first
        self.last_address = right[-1].last

        lpivot, rpivot = len(left)//2, len(right)//2
        self.left = left[0] if len(left) == 1 else RangeTreeNode(left[:lpivot], left[lpivot:])
        self.right = right[0] if len(right) == 1 else RangeTreeNode(right[:rpivot], right[rpivot:])

    def get(self, address):
        if address not in self:
            raise IndexError("Address not found")
        return self.left if (address < self.middle_address) else self.right

    def __contains__(self, address):
        return self.start_address <= address <= self.last_address

class RangeTree(object):
    def __init__(self, rlist):
        pivot = len(rlist)//2
        self.root = rlist[0] if len(rlist) == 1 else RangeTreeNode(rlist[:pivot], rlist[pivot:])

    def get(self, address):
        current = self.root
        while True:
            if isinstance(current, FunctionDisassembly):
                if address not in current:
                    raise IndexError("Address not found")
                return current
            current = current.get(address)

class MemMap(object):
    def __init__(self, rtree):
        self.rtree = rtree

    def print_trace(self, trace):
        def prn_addr(addr):
            fdis = self.rtree.get(addr)
            print(colorize("--^ {0:08x} {1}".format(addr, fdis.name), 'bright_yellow'))
            fdis.print_context_for(addr)
        for step_address in reversed(trace.stack):
            prn_addr(step_address)
        prn_addr(trace.exception_address)

class MemMapFile(object):
    def __init__(self, path):
        self.fd = open(path)
        self.line_no = 0
        self.buffer = None

    def next(self):
        if self.buffer is None:
            next_line = self.fd.readline()
        else:
            next_line = self.buffer
            self.buffer = None
        if next_line == "":
            raise StopIteration()
        self.line_no += 1
        return next_line[:-1]

    def rollback(self, line):
        self.buffer = line + '\n'

        self.line_no -= 1

object_header_re = re.compile("[0-9a-f]+ <(?P<name>[^>]+)>")
assembly_re = re.compile("^ *(?P<addr>[0-9a-f]+):\t(?P<code>.*)$")

def read_memmap(mmfile):
    reading_disassembly = False
    current_object = None
    object_list = []
    try:
        while True:
            line = mmfile.next()

            if not line:
                continue
            elif not reading_disassembly:
                if line.startswith('Disassembly of section'):
                    reading_disassembly = True
                    current_object = None
            else:
                matched = object_header_re.match(line)
                if not matched:
                    continue
                current_object = FunctionDisassembly(matched.group('name'))
                object_list.append(current_object)
                # Skip next line
                mmfile.next()
                while True:
                    current_object.new_block()
                    while True:
                        line = mmfile.next()
                        assm = assembly_re.match(line)
                        if assm:
                            break
                        current_object.add_text(line)

                    while assm:
                        current_object.add_assembly(int(assm.group('addr'), 16), assm.group('code'))
                        line = mmfile.next()
                        assm = assembly_re.match(line)

                    if not line.strip():
                        current_object.update()
                        current_object = None
                        break
                    else:
                        mmfile.rollback(line)

    except StopIteration:
        if current_object is not None:
            current_object.update()

    if object_list:
        return MemMap(RangeTree(object_list))

def read_stack_trace(fobject):
    reading_st = False
    line_no = 0
    ip = None
    stack = []
    for line in fobject:
        line_no += 1
        if reading_st:
            if "IP:" in line:
                ip = int(line.split(',')[0].split('x')[-1], 16)
            elif line.startswith("--^"):
                addresses = line.split('--^')[1:]
                stack.extend((int(x.split('x')[1], 16) for x in addresses))
            elif "Suspending" in line:
                break
        elif line.startswith("Stack Trace"):
            reading_st = True

    return Trace(ip, stack)

if __name__ == '__main__':
    with open(sys.argv[2]) as trace:
        rt = read_memmap(MemMapFile(sys.argv[1]))
        st = read_stack_trace(trace)
        rt.print_trace(st)
