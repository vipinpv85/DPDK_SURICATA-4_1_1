extern crate nom;
extern crate kerberos_parser;

use nom::IResult;
use kerberos_parser::krb5::*;
use kerberos_parser::krb5_parser::*;

#[test]
fn test_parse_kerberos_string() {
    let bytes = &[0x1b, 0x04, 0x63, 0x69, 0x66, 0x73];
    let empty = &b""[..];
    let expected = IResult::Done(empty,Realm(String::from("cifs")));

    let res = parse_krb5_realm(bytes);
    assert_eq!(res,expected);
}

#[test]
fn test_parse_realm() {
    let bytes = &[0x1b, 0x05, 0x4a, 0x6f, 0x6e, 0x65, 0x73];
    let empty = &b""[..];
    let expected = IResult::Done(empty,Realm(String::from("Jones")));

    let res = parse_krb5_realm(bytes);
    assert_eq!(res,expected);
}

#[test]
fn test_parse_principalname() {
    let bytes = &[
        0x30, 0x81, 0x11,
            0xa0, 0x03, 0x02, 0x01, 0x00,
            0xa1, 0x0a, 0x30, 0x81, 0x07, 0x1b, 0x05, 0x4a, 0x6f, 0x6e, 0x65, 0x73
    ];
    let empty = &b""[..];
    let expected = IResult::Done(empty,PrincipalName{
        name_type: NameType(0),
        name_string: vec![String::from("Jones")]
    });

    let res = parse_krb5_principalname(bytes);
    assert_eq!(res,expected);
}

#[test]
fn test_parse_principalname2() {
    let bytes = &[
        0x30, 0x27,
        0xa0, 0x03, 0x02, 0x01, 0x02,
        0xa1, 0x20, 0x30, 0x1e,
            0x1b, 0x04, 0x63, 0x69, 0x66, 0x73,
            0x1b, 0x16, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x2d, 0x50, 0x43, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x6f, 0x73, 0x6f, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
    ];
    let empty = &b""[..];
    let expected = IResult::Done(empty,PrincipalName{
        name_type: NameType::KRB_NT_SRV_INST,
        name_string: vec![String::from("cifs"),String::from("Admin-PC.contoso.local")]
    });

    let res = parse_krb5_principalname(bytes);
    assert_eq!(res,expected);
}

static KRB5_TICKET: &'static [u8] = include_bytes!("../assets/krb5-ticket.bin");
#[test]
fn test_parse_ticket() {
    let bytes = KRB5_TICKET;

    let res = parse_krb5_ticket(bytes);
    // println!("parse_krb5_ticket: {:?}", res);
    match res {
        IResult::Done(rem,tkt) => {
            assert!(rem.is_empty());
            assert_eq!(tkt.tkt_vno, 5);
            assert_eq!(tkt.realm, Realm(String::from("CONTOSO.LOCAL")));
            assert_eq!(tkt.sname, PrincipalName{ name_type:NameType::KRB_NT_SRV_INST, name_string:vec![String::from("cifs"),String::from("Admin-PC.contoso.local")] });
            let enc = parse_encrypted(tkt.enc_part).unwrap().1;
            // println!("enc: {:?}", enc);
            assert_eq!(enc.etype,EncryptionType::AES256_CTS_HMAC_SHA1_96);
            assert_eq!(enc.kvno,Some(1));
        },
        _ => assert!(false)
    }
}

static AS_REQ: &'static [u8] = include_bytes!("../assets/as-req.bin");
#[test]
fn test_parse_as_req() {
    let bytes = AS_REQ;

    let res = parse_as_req(bytes);
    // println!("parse_as_req: {:?}", res);
    match res {
        IResult::Done(rem,req) => {
            assert!(rem.is_empty());
            assert_eq!(req.pvno, 5);
            assert_eq!(req.msg_type, MessageType::KRB_AS_REQ);
            assert_eq!(req.req_body.realm, Realm(String::from("DENYDC")));
            assert_eq!(req.req_body.cname,
                       Some(PrincipalName{ name_type:NameType::KRB_NT_PRINCIPAL, name_string:vec![String::from("des")] }));
            assert_eq!(req.req_body.sname,
                       Some(PrincipalName{ name_type:NameType::KRB_NT_SRV_INST, name_string:vec![String::from("krbtgt"),String::from("DENYDC")] }));
        },
        _ => assert!(false)
    }
}

static AS_REP: &'static [u8] = include_bytes!("../assets/as-rep.bin");
#[test]
fn test_parse_as_rep() {
    let bytes = AS_REP;

    let res = parse_as_rep(bytes);
    // println!("parse_as_rep: {:?}", res);
    match res {
        IResult::Done(rem,req) => {
            assert!(rem.is_empty());
            assert_eq!(req.pvno, 5);
            assert_eq!(req.msg_type, MessageType::KRB_AS_REP);
            assert_eq!(req.crealm, Realm(String::from("DENYDC.COM")));
            assert_eq!(req.cname,
                       PrincipalName{ name_type:NameType::KRB_NT_PRINCIPAL, name_string:vec![String::from("des")] });
        },
        _ => assert!(false)
    }
}

static AP_REQ: &'static [u8] = include_bytes!("../assets/ap-req.bin");
#[test]
fn test_parse_ap_req() {
    let bytes = AP_REQ;

    let res = parse_ap_req(bytes);
    // println!("parse_ap_req: {:?}", res);
    match res {
        IResult::Done(rem,req) => {
            assert!(rem.is_empty());
            assert_eq!(req.pvno, 5);
            assert_eq!(req.msg_type, MessageType::KRB_AP_REQ);
            assert_eq!(req.ticket.realm, Realm(String::from("DENYDC.COM")));
            assert_eq!(req.ticket.sname,
                       PrincipalName{ name_type:NameType::KRB_NT_SRV_INST, name_string:vec![String::from("krbtgt"),String::from("DENYDC.COM")] });
        },
        _ => assert!(false)
    }
}

static KRB_ERROR: &'static [u8] = include_bytes!("../assets/krb-error.bin");
#[test]
fn test_parse_krb_error() {
    let bytes = KRB_ERROR;

    let res = parse_krb_error(bytes);
    // println!("parse_krb_error: {:?}", res);
    match res {
        IResult::Done(rem,err) => {
            assert!(rem.is_empty());
            assert_eq!(err.pvno, 5);
            assert_eq!(err.msg_type, MessageType::KRB_ERROR);
            assert_eq!(err.error_code, ErrorCode::KDC_ERR_ETYPE_NOSUPP);
            assert_eq!(err.realm, Realm(String::from("DENYDC")));
            assert_eq!(err.sname,
                       PrincipalName{ name_type:NameType::KRB_NT_SRV_INST, name_string:vec![String::from("krbtgt"),String::from("DENYDC")] });
        },
        _ => assert!(false)
    }
}

#[test]
fn test_parse_int32() {
    let empty = &b""[..];
    assert_eq!(parse_der_int32(&[0x02, 0x01, 0xff]),IResult::Done(empty,-1));
    assert_eq!(parse_der_int32(&[0x02, 0x01, 0x01]),IResult::Done(empty,1));
    assert_eq!(parse_der_int32(&[0x02, 0x02, 0xff, 0xff]),IResult::Done(empty,-1));
    assert_eq!(parse_der_int32(&[0x02, 0x02, 0x01, 0x23]),IResult::Done(empty,0x123));
    assert_eq!(parse_der_int32(&[0x02, 0x03, 0xff, 0xff, 0xff]),IResult::Done(empty,-1));
    assert_eq!(parse_der_int32(&[0x02, 0x03, 0x01, 0x23, 0x45]),IResult::Done(empty,0x12345));
    assert_eq!(parse_der_int32(&[0x02, 0x04, 0xff, 0xff, 0xff, 0xff]),IResult::Done(empty,-1));
    assert_eq!(parse_der_int32(&[0x02, 0x04, 0x01, 0x23, 0x45, 0x67]),IResult::Done(empty,0x1234567));
}

#[test]
fn test_principalname_display() {
    let pn = PrincipalName{
        name_type:  NameType::KRB_NT_SRV_INST,
        name_string: vec!["krb5".to_string(), "DOMAIN.COM".to_string()],
    };
    assert_eq!("krb5/DOMAIN.COM",format!("{}", pn));
}
