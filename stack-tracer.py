#!/usr/bin/env python

from __future__ import print_function

import os
import re
import sys
from collections import namedtuple

Assembly = namedtuple('Assembly', 'address text')
Trace = namedtuple('Trace', 'exception_address stack')

class CodeLine(object):
    def __init__(self, path, line_no):
        self.path = path
        self.line_no = line_no
        self.code = []

    def __contains__(self, address):
        return any(c.address == address for c in self.code)

    def print(self):
        try:
            code_lines = open(self.path).readlines()
            for ln in range(self.line_no - 5, self.line_no + 6):
                if ln >= 1:
                    marker = '>' if ln == self.line_no else ' '
                    print("  {0} {1}".format(marker, code_lines[ln-1].strip()))
        except IOError:
            print("  ????")

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

    def add_line(self, line_no, path):
        self.lines.append(CodeLine(path, int(line_no)))

    def add_assembly(self, address, code):
        if not self.lines:
            self.lines.append(CodeLine(None, None))
        self.lines[-1].code.append(Assembly(address, code))

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
            print("--^ {0:08x} {1}".format(addr, fdis.name))
            fdis.print_context_for(addr)
        for step_address in reversed(trace.stack):
            prn_addr(step_address)
        prn_addr(trace.exception_address)

object_header_re = re.compile("[0-9a-f]+ <(?P<name>[^>]+)>")
assembly_re = re.compile("^ *(?P<addr>[0-9a-f]+):\t(?P<code>.*)$")

def read_memmap(fobject):
    reading_disassembly = False
    reading_object = False
    current_object = None
    object_list = []
    line_no = 0
    for line in fobject:
        line_no += 1
        line = line.strip()

        if not line:
            continue
        elif line.startswith('Disassembly of section'):
                reading_disassembly = True
                if current_object:
                    current_object.update()
                current_object = None
                reading_object = False
        else:
            matched = object_header_re.match(line)
            if matched:
                if current_object:
                    current_object.update()
                current_object = FunctionDisassembly(matched.group('name'))
                object_list.append(current_object)
            elif current_object is not None:
                assm = assembly_re.match(line)

                if line.endswith('():'):
                    continue
                elif assm:
                    current_object.add_assembly(int(assm.group('addr'), 16), assm.group('code'))
                else:
                    try:
                        path, pline_no = line.split(':')
                        if pline_no.isdigit():
                            current_object.add_line(pline_no, os.path.abspath(path))
                    except ValueError:
                        # Probably embedded code. Ignore
                        pass

    if object_list:
        object_list[-1].update()
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
    with open(sys.argv[1]) as mmfile:
        with open(sys.argv[2]) as trace:
            rt = read_memmap(mmfile)
            st = read_stack_trace(trace)
            rt.print_trace(st)
