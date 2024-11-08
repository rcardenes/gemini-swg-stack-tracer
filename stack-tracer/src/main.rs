use std::{fs::File, io::{BufRead, BufReader, Read}, path::{Path, PathBuf}};

use anyhow::Result;
use regex::{Captures, Regex};

static USAGE_STRING: &str = r#"
Stack Tracer:

    stack-tracer <mem-map file> <stack trace>

The stack trace can have any content (comments, etc). The only
relevant lines are the ones between the "Stack Trace:" line and
"Suspending [...]". Eg:

   Stack Trace:
    IP: 0x0012EFC8, LR: 0x0011D450
   --^ 0x0001A48C--^ 0x00018F9C--^ 0x000EC690--^ 0x000F0E64--^ 0x000EE044
   --^ 0x000E0AB8--^ 0x000E7094--^ 0x00136048--^ 0x00135F6C
   Suspending faulting task (0x0A010012)

Everything else will be ignored. Only one stack trace (the first) will be
processed.
"#;

enum Color {
    Red,
    BrightRed,
    Green,
    BrightGreen,
    Yellow,
    BrightYellow,
}

impl ToString for Color {
    fn to_string(&self) -> String {
        match self {
            Color::Red => "31",
            Color::BrightRed => "31;1",
            Color::Green => "32",
            Color::BrightGreen => "32;1",
            Color::Yellow => "33",
            Color::BrightYellow => "33;1",
        }.into()
    }
}

struct Assembly {
    address: usize,
    text: String,
}

impl Assembly {
    fn new(address: &str, text: &str) -> Self {
        Assembly {
            address: usize::from_str_radix(address, 16).expect(&format!("Not an hex number: {address}")),
            text: text.into()
        }
    }
}

struct Trace {
    exception_address: usize,
    stack: Vec<usize>,
}

struct CodeBlock {
    text: Vec<String>,
    code: Vec<Assembly>,
}

impl CodeBlock {
    fn new() -> Self {
        CodeBlock {
            text: vec![],
            code: vec![],
        }
    }

    fn contains(&self, address: usize) -> bool {
        self.code.iter().any(|a| a.address == address)
    }

    fn print(&self, mark: Option<usize>) {
        for t in self.text.iter() {
            println!("    {t}");
        }
        for c in self.code.iter() {
            let text = format!("    {:08x}  {}", c.address, c.text);
            let printable = match mark {
                Some(addr) if addr == c.address => colorize(&text, Color::BrightGreen),
                _ => text
            };
            println!("{printable}");
        }
    }
}

struct FunctionDisassembly {
    name: String,
    first: usize,
    last: usize,
    lines: Vec<CodeBlock>,
}

impl FunctionDisassembly {
    fn new(name: &str) -> Self {
        FunctionDisassembly {
            name: name.to_string(),
            first: 0,
            last: 0,
            lines: vec![]
        }
    }

    fn contains(&self, address: usize) -> bool {
        (self.first <= address) && (address <= self.last)
    }

    fn new_block(mut self) -> Self {
        self.lines.push(CodeBlock::new());
        self
    }

    fn add_assembly(mut self, address: &str, code: &str) -> Self {
        self.lines.last_mut().unwrap().code.push(Assembly::new(address, code));
        self
    }

    fn add_text(mut self, line: &str) -> Self {
        self.lines.last_mut().unwrap().text.push(line.into());
        self
    }

    fn update(&mut self) {
        if self.lines.is_empty() {
            panic!("Updating an empty FunctionDisassembly!");
        }

        self.first = self.lines.first().unwrap().code.first().unwrap().address;
        self.last = self.lines.last().unwrap().code.last().unwrap().address;
    }

    fn print_context_for(&self, address: usize) {
        for line in self.lines.iter() {
            if line.contains(address) {
                line.print(Some(address));
                break
            }
        }
    }
}

struct MemMapFile<R> {
    fd: BufReader<R>,
    line_no: usize,
    buffer: Option<String>,
    invalidated: bool,
}

impl<R> MemMapFile<R>
    where R: Read
{
    fn new(fd: BufReader<R>) -> Self {
        MemMapFile {
            fd,
            line_no: 0,
            buffer: None,
            invalidated: false,
        }
    }

    fn next(&mut self) -> Option<String> {
        if self.invalidated {
            None
        } else {
            let next_line = match self.buffer.take() {
                Some(line) => line,
                None => {
                    let mut line = String::new();
                    if self.fd.read_line(&mut line).unwrap() == 0 {
                        return None
                    }
                    if line.ends_with("\n") {
                        line.pop();
                    }
                    line
                }
            };
            self.line_no += 1;
            Some(next_line)
        }
    }

    fn  rollback(&mut self, line: String) {
        self.buffer = Some(line);
        self.line_no -= 1;
    }

    fn done(&mut self) {
        self.invalidated = true;
    }
}

enum RangeTreeNode {
    Single(FunctionDisassembly),
    Ranged {
        start_address: usize,
        middle_address: usize,
        last_address: usize,
        left: Box<RangeTreeNode>,
        right: Box<RangeTreeNode>,
    }
}

impl RangeTreeNode {
    fn single(leaf: FunctionDisassembly) -> Self {
        RangeTreeNode::Single(leaf)
    }

    fn new(mut obj_list: Vec<FunctionDisassembly>) -> Self {
        if obj_list.len() == 1 {
            RangeTreeNode::Single(obj_list.pop().unwrap())
        } else {
            let pivot = obj_list.len() / 2;
            let mut right = obj_list.split_off(pivot);
            let mut left = obj_list;
            let start_address = left.first().unwrap().first;
            let middle_address = right.first().unwrap().first;
            let last_address = right.last().unwrap().last;

            RangeTreeNode::Ranged {
                start_address,
                middle_address,
                last_address,
                left: Box::new(if left.len() == 1 { RangeTreeNode::Single(left.pop().unwrap()) } else { RangeTreeNode::new(left) }),
                right: Box::new(if right.len() == 1 { RangeTreeNode::Single(right.pop().unwrap()) } else { RangeTreeNode::new(right) }),
            }
        }
    }

    fn contains(&self, address: usize) -> bool {
        match self {
            RangeTreeNode::Single(fd) => {
                fd.contains(address)
            }
            RangeTreeNode::Ranged { start_address, last_address, .. } => {
                (address >= *start_address) && (address <= *last_address)
            }
        }
    }

    fn get(&self, address: usize) -> &FunctionDisassembly {
        if !self.contains(address) {
            panic!("Address not found: {address:#010x}")
        }

        match self {
            RangeTreeNode::Single(fa) => fa,
            RangeTreeNode::Ranged { middle_address, left, right, ..} => {
            }
        }
    }
}

struct RangeTree {
    root: RangeTreeNode,
}

impl RangeTree {
    fn new(object_list: Vec<FunctionDisassembly>) -> Self {
        RangeTree {
            root: RangeTreeNode::new(object_list)
        }
    }

    fn get(&self, address: usize) -> &RangeTreeNode {
        todo!()
    }
}

struct MemMap {
    rtree: RangeTree,
}

impl MemMap {
    fn new(rtree: RangeTree) -> Self {
        MemMap {
            rtree
        }
    }
}

enum MemMapReaderState {
    Init,
    FindingObject,
    ProcessingObject,
    ProcessingAssembly,
}

fn read_memmap<R>(mmfile: MemMapFile<R>) -> MemMap
    where R: Read,
{
    let mut mmfile = mmfile;

    let mut reading_disassembly = false;
    let mut current_object: Option<FunctionDisassembly> = None;
    let mut object_list: Vec<FunctionDisassembly> = vec![];
    let mut status = MemMapReaderState::Init;

    let object_header_re = Regex::new("[0-9a-f]+ <(?P<name>[^>]+)>").unwrap();
    let assembly_re = Regex::new("^ *(?P<addr>[0-9a-f]+):\t(?P<code>.*)$").unwrap();

    loop {
        match mmfile.next() {
            Some(line) => {
                match status {
                    MemMapReaderState::Init => {
                        if line.starts_with("Disassembly of section") {
                            status = MemMapReaderState::FindingObject;
                            current_object = None;
                        }
                    }
                    MemMapReaderState::FindingObject => {
                        match object_header_re.captures(&line) {
                            Some(m) => {
                                status = MemMapReaderState::ProcessingObject;
                                let mut new_object = FunctionDisassembly::new(&m["name"]);
                                let old_object = current_object.replace(new_object.new_block());
                                if let Some(object) = old_object {
                                    object_list.push(object);
                                }
                                // Skip the next line, it's redundant
                                mmfile.next();
                            },
                            None => continue,
                        };
                    }
                    MemMapReaderState::ProcessingObject => {
                        if assembly_re.is_match(&line) {
                            status = MemMapReaderState::ProcessingAssembly;
                            mmfile.rollback(line);
                        } else {
                            current_object = current_object.map(|fa| {
                                fa.add_text(&line)
                            });
                        }
                    }
                    MemMapReaderState::ProcessingAssembly => {
                        if let Some(cap) = assembly_re.captures(&line) {
                            current_object = current_object.map(|fa| {
                                fa.add_assembly(&cap["addr"], &cap["code"])
                            });
                        } else if line.starts_with("Contents of") {
                            mmfile.done();
                        } else if line.trim().is_empty() {
                            if let Some(mut obj) = current_object.take() {
                                obj.update();
                                object_list.push(obj);
                            }
                            status = MemMapReaderState::FindingObject;
                        } else {
                            current_object = current_object.map(|mut fa| {
                                fa.new_block()
                            });
                            mmfile.rollback(line);
                            status = MemMapReaderState::ProcessingObject;
                        }
                    }
                };
            }
            None => {
                if let Some(mut object) = current_object {
                   object.update();
                   object_list.push(object);
                   // TODO: And now... do something with it?
                }
                break;
            }
        }
    }

    MemMap::new(RangeTree::new(object_list))
}

fn usage(error_message: Option<&str>) -> ! {
    if let Some(msg) = error_message {
        eprintln!("{}", colorize(msg, Color::BrightRed));
    }
    eprintln!("{USAGE_STRING}");

    std::process::exit(1);
}

fn colorize(text: &str, color: Color) -> String {
    format!("\x1b[{0}m{1}\x1b[0m", color.to_string(), text)
}

fn get_path(index: usize) -> PathBuf {
    if let Some(arg) = std::env::args().nth(index) {
        Path::new(&arg).to_path_buf()
    } else {
        usage(None);
    }
}

fn get_file(path: &Path) -> File {
    match File::open(path) {
        Ok(fd) => fd,
        Err(error) => {
            let fname = path.to_string_lossy();
            let msg = format!("{}: {error}", fname);
            usage(Some(&msg));
        }
    }
}

fn get_streams() -> (BufReader<File>, BufReader<File>) {
    (
        BufReader::new(get_file(&get_path(1))),
        BufReader::new(get_file(&get_path(2)))
    )
}

fn main() {
    let (map_file, _trace_file) = get_streams();
    let _rt = read_memmap(MemMapFile::new(map_file));

    todo!()
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    #[test]
    fn test_object_header_regex() {
        let oh_re = Regex::new("[0-9a-f]+ <(?P<name>[^>]+)>:").unwrap();

        if let Some(caps) = oh_re.captures("00003000 <__init>:") {

            assert_eq!(&caps[1], "__init");
            assert_eq!(&caps["name"], "__init");
        } else {
            panic!("The object_header regex is not matching anything")
        }
    }

    #[test]
    fn test_assembly_regex() {
        let a_re = Regex::new("^ *(?P<addr>[0-9a-f]+):\t(?P<code>.*)$").unwrap();

        if let Some(caps) = a_re.captures("3004:\t7c 08 02 a6\tmflr    r0") {
            assert_eq!(&caps[1], "3004");
            assert_eq!(&caps["addr"], "3004");
            assert_eq!(&caps[2], "7c 08 02 a6\tmflr    r0");
            assert_eq!(&caps["code"], "7c 08 02 a6\tmflr    r0");
        } else {
            panic!("The assembly regex is not matching anything")
        }
    }
}
