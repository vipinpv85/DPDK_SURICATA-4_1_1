use nom::{be_i8,be_u8,be_u16,be_u32,be_u64,ErrorKind,IResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtpMode(pub u8);

#[allow(non_upper_case_globals)]
impl NtpMode {
    pub const Reserved          : NtpMode = NtpMode(0);
    pub const SymmetricActive   : NtpMode = NtpMode(1);
    pub const SymmetricPassive  : NtpMode = NtpMode(2);
    pub const Client            : NtpMode = NtpMode(3);
    pub const Server            : NtpMode = NtpMode(4);
    pub const Broadcast         : NtpMode = NtpMode(5);
    pub const NtpControlMessage : NtpMode = NtpMode(6);
    pub const Private           : NtpMode = NtpMode(7);
}

#[derive(Debug,PartialEq)]
pub struct NtpPacket<'a> {
    pub li: u8,
    pub version: u8,
    pub mode: NtpMode,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub ref_id:u32,
    pub ts_ref:u64,
    pub ts_orig:u64,
    pub ts_recv:u64,
    pub ts_xmit:u64,

    pub extensions:Vec<NtpExtension<'a>>,
    pub auth: Option<NtpMac<'a>>
}

impl<'a> NtpPacket<'a> {
    pub fn get_precision(&self) -> f32 {
        2.0_f32.powf(self.precision as f32)
    }
}

#[derive(Debug,PartialEq)]
pub struct NtpExtension<'a> {
    pub field_type: u16,
    pub length: u16,
    pub value: &'a[u8],
    /*padding*/
}

#[derive(Debug,PartialEq)]
pub struct NtpMac<'a> {
    pub key_id: u32,
    pub mac:    &'a[u8],
}

pub fn parse_ntp_extension(i: &[u8]) -> IResult<&[u8],NtpExtension> {
    do_parse!(
        i,
        field_type: be_u16 >>
        length:     be_u16 >> // len includes the padding
        value:      take!(length) >>
        (
            NtpExtension{
                field_type,
                length,
                value,
            }
        )
    )
}

fn parse_ntp_mac(i: &[u8]) -> IResult<&[u8],NtpMac> {
   do_parse!(
       i,
       key_id: be_u32 >>
       mac:    take!(16) >>
       ( NtpMac{ key_id, mac} )
   )
}

// optional fields, See section 7.5 of [RFC5905] and [RFC7822]
// extensions, key ID and MAC
//
// check length: if == 20, only MAC
//               if >  20, ext + MAC
//               if ==  0, nothing
//               else      error
fn parse_extensions_and_auth(i:&[u8]) -> IResult<&[u8],(Vec<NtpExtension>,Option<NtpMac>)> {
    if i.is_empty() { IResult::Done(i,(Vec::new(),None)) }
    else if i.len() == 20 {
        parse_ntp_mac(i).map(|m| (Vec::new(),Some(m)))
    }
    else if i.len() > 20 {
        do_parse!(
            i,
            v: flat_map!(
                take!(i.len() - 20),
                many1!(complete!(parse_ntp_extension))
               ) >>
            m: parse_ntp_mac >>
               eof!() >>
            ( (v,Some(m)) )
        )
    } else {
        IResult::Error(error_code!(ErrorKind::Eof))
    }
}

named!(pub parse_ntp<NtpPacket>,
   do_parse!(
       b0:              bits!(
                            tuple!(take_bits!(u8,2),take_bits!(u8,3),take_bits!(u8,3))
                        ) >>
       stratum:         be_u8 >>
       poll:            be_i8 >>
       precision:       be_i8 >>
       root_delay:      be_u32 >>
       root_dispersion: be_u32 >>
       ref_id:          be_u32 >>
       ts_ref:          be_u64 >>
       ts_orig:         be_u64 >>
       ts_recv:         be_u64 >>
       ts_xmit:         be_u64 >>
       ext_and_auth:    parse_extensions_and_auth >>
       (
           NtpPacket {
               li:b0.0,
               version:b0.1,
               mode:NtpMode(b0.2),
               stratum,
               poll,
               precision,
               root_delay,
               root_dispersion,
               ref_id,
               ts_ref,
               ts_orig,
               ts_recv,
               ts_xmit,
               extensions: ext_and_auth.0,
               auth: ext_and_auth.1
           }
   ))
);

#[cfg(test)]
mod tests {
    use ntp::*;
    use nom::IResult;

static NTP_REQ1: &'static [u8] = &[
    0xd9, 0x00, 0x0a, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x90,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xc5, 0x02, 0x04, 0xec, 0xec, 0x42, 0xee, 0x92
];

#[test]
fn test_ntp_packet_simple() {
    let empty = &b""[..];
    let bytes = NTP_REQ1;
    let expected = IResult::Done(empty,NtpPacket{
        li:3,
        version:3,
        mode:NtpMode::SymmetricActive,
        stratum:0,
        poll:10,
        precision:-6,
        root_delay:0,
        root_dispersion:0x010290,
        ref_id:0,
        ts_ref:0,
        ts_orig:0,
        ts_recv:0,
        ts_xmit:14195914391047827090u64,
        extensions:Vec::new(),
        auth:None,
    });
    let res = parse_ntp(&bytes);
    assert_eq!(res, expected);
}

static NTP_REQ2: &'static [u8] = &[
    0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xcc, 0x25, 0xcc, 0x13, 0x2b, 0x02, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x52, 0x80, 0x0c, 0x2b, 0x59, 0x00, 0x64, 0x66,
    0x84, 0xf4, 0x4c, 0xa4, 0xee, 0xce, 0x12, 0xb8
];

#[test]
fn test_ntp_packet_mac() {
    let empty = &b""[..];
    let bytes = NTP_REQ2;
    let expected = IResult::Done(empty,NtpPacket{
        li:0,
        version:4,
        mode:NtpMode::Client,
        stratum:0,
        poll:0,
        precision:0,
        root_delay:12,
        root_dispersion:0,
        ref_id:0,
        ts_ref:0,
        ts_orig:0,
        ts_recv:0,
        ts_xmit:14710388140573593600,
        extensions:Vec::new(),
        auth:Some(NtpMac{key_id:1,mac:&bytes[52..]}),
    });
    let res = parse_ntp(&bytes);
    assert_eq!(res, expected);
}

static NTP_REQ2B: &'static [u8] = &[
    0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xcc, 0x25, 0xcc, 0x13, 0x2b, 0x02, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x52, 0x80, 0x0c, 0x2b,
    0x59, 0x00, 0x64, 0x66, 0x84, 0xf4, 0x4c, 0xa4, 0xee, 0xce, 0x12, 0xb8,
];

#[test]
fn test_ntp_packet_extension() {
    let empty = &b""[..];
    let bytes = NTP_REQ2B;
    let expected = IResult::Done(empty,NtpPacket{
        li:0,
        version:4,
        mode:NtpMode::Client,
        stratum:0,
        poll:0,
        precision:0,
        root_delay:12,
        root_dispersion:0,
        ref_id:0,
        ts_ref:0,
        ts_orig:0,
        ts_recv:0,
        ts_xmit:14710388140573593600,
        extensions:vec![NtpExtension{
            field_type: 0,
            length: 0,
            value: empty
        }],
        auth:Some(NtpMac{key_id:1,mac:&bytes[56..]}),
    });
    let res = parse_ntp(&bytes);
    assert_eq!(res, expected);
}

}
