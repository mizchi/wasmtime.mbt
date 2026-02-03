///|
/// Read a little-endian u32 from bytes.
pub fn read_u32_le(bytes : Bytes, offset : Int) -> UInt64 {
  let view = bytes.sub(start=offset, end=offset + 4)
  let mut value = 0UL
  for i, byte in view {
    value = value | (byte.to_uint64() << (i * 8))
  }
  value
}

///|
/// Read a little-endian u64 from bytes.
pub fn read_u64_le(bytes : Bytes, offset : Int) -> UInt64 {
  let view = bytes.sub(start=offset, end=offset + 8)
  let mut value = 0UL
  for i, byte in view {
    value = value | (byte.to_uint64() << (i * 8))
  }
  value
}
