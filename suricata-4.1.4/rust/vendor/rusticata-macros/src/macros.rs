//! Helper macros

use nom::{IResult,rest};
use nom::HexDisplay;

/// Helper macro for nom parsers: raise error if the condition is false
#[macro_export]
macro_rules! error_if (
  ($i:expr, $cond:expr, $err:expr) => (
    {
      if $cond {
        IResult::Error(error_position!($err,$i))
        // for nom4:
        // Err(Err::Error(error_position!($i, $err)))
      } else {
        IResult::Done($i, ())
        // for nom4:
        // Ok(($i, ()))
      }
    }
  );
);

/// Helper macro for nom parsers: run first parser if condition is true, else second parser
#[macro_export]
macro_rules! cond_else (
  ($i:expr, $cond:expr, $expr_then:expr, $expr_else:expr) => (
    {
      if $cond { $expr_then }
      else { $expr_else }
    }
  );
);

/// Dump the remaining bytes to stderr, formatted as hex
pub fn dbg_dmp_rest(i:&[u8]) -> IResult<&[u8],()> {
    map!(
        i,
        peek!(rest),
        |r| eprintln!("\n{}\n", r.to_hex(16))
    )
}

/// Read an entire slice as a big-endian value.
///
/// Returns the value as `u64`. This function checks for integer overflows, and returns a
/// `Result::Err` value if the value is too big.
pub fn bytes_to_u64(s: &[u8]) -> Result<u64, &'static str> {
    let mut u : u64 = 0;

    if s.len() == 0 { return Err("empty"); };
    if s.len() > 8 { return Err("overflow"); }
    for &c in s {
        let u1 = u << 8;
        u = u1 | (c as u64);
    }

    Ok(u)
}

/// Read a slice as a big-endian value.
#[macro_export]
macro_rules! parse_hex_to_u64 (
    ( $i:expr, $size:expr ) => (
        map_res!($i, take!(($size as usize)), $crate::bytes_to_u64)
    );
);

named_attr!(#[doc = "Read 3 bytes as an unsigned integer"],
            pub parse_uint24<&[u8], u64>, parse_hex_to_u64!(3));

//named!(parse_hex4<&[u8], u64>, parse_hex_to_u64!(4));


/// Parse a slice and return a fixed-sized array of bytes
///
/// This creates a copy of input data
/// Uses unsafe code
#[macro_export]
macro_rules! slice_fixed(
    ( $i:expr, $count:expr ) => (
        {
            let cnt = $count;
            let ires: IResult<_,_> = if $i.len() < cnt {
                IResult::Incomplete(Needed::Size(cnt))
            } else {
                let mut res: [u8; $count] = unsafe{[::std::mem::uninitialized(); $count as usize]};
                unsafe{::std::ptr::copy($i.as_ptr(), res.as_mut_ptr(), cnt)};
                IResult::Done(&$i[cnt..],res)
            };
            ires
        }
    );
);



#[cfg(test)]
mod tests{

    use nom::{be_u8,IResult,Needed,ErrorKind};

#[test]
#[allow(unsafe_code)]
fn test_slice_fixed() {
    let empty = &b""[..];
    let b = &[0x01, 0x02, 0x03, 0x04, 0x05];

    let res = slice_fixed!(b, 4);
    assert_eq!(res, IResult::Done(&b[4..], [1, 2, 3, 4]));

    // can we still use the result ?
    match res {
        IResult::Done(rem, _) => {
            let res2 = be_u8(rem);
            assert_eq!(res2, IResult::Done(empty,5));
        },
        _ => (),
    }
}

#[test]
#[allow(unsafe_code)]
fn test_slice_fixed_incomplete() {
    let b = &[0x01, 0x02, 0x03, 0x04, 0x05];
    let res = slice_fixed!(b, 8);
    assert_eq!(res, IResult::Incomplete(Needed::Size(8)));
}

#[test]
fn test_error_if() {
    let empty = &b""[..];
    let res : IResult<&[u8],(),u32> = error_if!(empty, true, ErrorKind::Tag);
    assert_eq!(res, IResult::Error(ErrorKind::Tag))
    // for nom4:
    // assert_eq!(res, Err(Err::Error(error_position!(empty, ErrorKind::Tag))))
}

}
