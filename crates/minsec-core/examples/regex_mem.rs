//! Heap cost of compiling filters. `cargo run --release -p minsec-core --example regex_mem`
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size(), Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        System.dealloc(p, l)
    }
}
#[global_allocator]
static A: Counting = Counting;

fn kb() -> usize {
    LIVE.load(Relaxed) / 1024
}

fn main() {
    let before = kb();
    let mut keep = Vec::new();
    for name in minsec_core::builtin::names() {
        let b = kb();
        let def = minsec_core::builtin::get(name).unwrap().unwrap();
        let n = def.patterns.len();
        let f = minsec_core::CompiledFilter::compile(def).unwrap();
        println!("{name:<14} {n:>2} patterns  {:>6} KB", kb() - b);
        keep.push(f);
    }
    println!("total {} KB for {} filters", kb() - before, keep.len());
    if let Some(p) = std::env::args().nth(1) {
        let b = kb();
        let re = regex::Regex::new(&minsec_core::filter::expand_tokens(&p)).unwrap();
        println!("custom: {} KB ({})", kb() - b, re.as_str().len());
        keep.clear();
        std::mem::forget(re);
    }
}
