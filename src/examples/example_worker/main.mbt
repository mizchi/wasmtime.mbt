///|
/// Simple wasm worker used by native host example.
pub fn run(x : Int) -> Int {
  x * 2
}

///|
fn main {
  let _ = run(21)
}
