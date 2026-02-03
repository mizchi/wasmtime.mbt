///|
/// Simple exported function for host interop test.
pub fn run(x : Int) -> Int {
  x + 1
}

///|
fn main {
  let result = run(41)
  println("guest:\{result}")
}
