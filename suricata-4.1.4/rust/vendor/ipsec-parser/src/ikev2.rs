use std::net::{IpAddr,Ipv4Addr,Ipv6Addr};
use std::fmt;
use ikev2_transforms::*;
use ikev2_notify::NotifyType;

/// Payload exchange type: SA, Auth, CreateChildSA, etc.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct IkeExchangeType(pub u8);

impl IkeExchangeType {
    pub const IKE_SA_INIT     : IkeExchangeType = IkeExchangeType(34);
    pub const IKE_AUTH        : IkeExchangeType = IkeExchangeType(35);
    pub const CREATE_CHILD_SA : IkeExchangeType = IkeExchangeType(36);
    pub const INFORMATIONAL   : IkeExchangeType = IkeExchangeType(37);
}

impl fmt::Debug for IkeExchangeType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            34 => f.write_str("IKE_SA_INIT"),
            35 => f.write_str("IKE_AUTH"),
            36 => f.write_str("CREATE_CHILD_SA"),
            37 => f.write_str("INFORMATIONAL"),
            n  => f.debug_tuple("IkeExchangeType").field(&n).finish(),
        }
    }
}

/// Protocol type: IKE, AH or ESP
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3.1
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProtocolID(pub u8);

impl ProtocolID {
    pub const IKE : ProtocolID = ProtocolID(1);
    pub const AH  : ProtocolID = ProtocolID(2);
    pub const ESP : ProtocolID = ProtocolID(3);
}

impl fmt::Debug for ProtocolID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            1 => f.write_str("IKE"),
            2 => f.write_str("AH"),
            3 => f.write_str("ESP"),
            n => f.debug_tuple("ProtocolID").field(&n).finish(),
        }
    }
}

pub const IKEV2_FLAG_INITIATOR : u8 = 0b1000;
pub const IKEV2_FLAG_VERSION   : u8 = 0b10000;
pub const IKEV2_FLAG_RESPONSE  : u8 = 0b100000;

/// The IKE Header
///
/// IKE messages use UDP ports 500 and/or 4500, with one IKE message per
/// UDP datagram.  Information from the beginning of the packet through
/// the UDP header is largely ignored except that the IP addresses and
/// UDP ports from the headers are reversed and used for return packets.
/// When sent on UDP port 500, IKE messages begin immediately following
/// the UDP header.  When sent on UDP port 4500, IKE messages have
/// prepended four octets of zeros.  These four octets of zeros are not
/// part of the IKE message and are not included in any of the length
/// fields or checksums defined by IKE.  Each IKE message begins with the
/// IKE header, denoted HDR in this document.  Following the header are
/// one or more IKE payloads each identified by a Next Payload field in
/// the preceding payload.  Payloads are identified in the order in which
/// they appear in an IKE message by looking in the Next Payload field in
/// the IKE header, and subsequently according to the Next Payload field
/// in the IKE payload itself until a Next Payload field of zero
/// indicates that no payloads follow.  If a payload of type "Encrypted"
/// is found, that payload is decrypted and its contents parsed as
/// additional payloads.  An Encrypted payload MUST be the last payload
/// in a packet and an Encrypted payload MUST NOT contain another
/// Encrypted payload.
///
/// The responder's SPI in the header identifies an instance of an IKE
/// Security Association.  It is therefore possible for a single instance
/// of IKE to multiplex distinct sessions with multiple peers, including
/// multiple sessions per peer.
///
/// All multi-octet fields representing integers are laid out in big
/// endian order (also known as "most significant byte first", or
/// "network byte order").
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.1
#[derive(Clone, Debug,PartialEq)]
pub struct IkeV2Header {
    pub init_spi: u64,
    pub resp_spi: u64,
    pub next_payload: IkePayloadType,
    pub maj_ver: u8,
    pub min_ver: u8,
    pub exch_type: IkeExchangeType,
    pub flags: u8,
    pub msg_id: u32,
    pub length: u32,
}

/// Payload type
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IkePayloadType(pub u8);

#[allow(non_upper_case_globals)]
impl IkePayloadType {
    pub const NoNextPayload             : IkePayloadType = IkePayloadType(0);
    pub const SecurityAssociation       : IkePayloadType = IkePayloadType(33);
    pub const KeyExchange               : IkePayloadType = IkePayloadType(34);
    pub const IdentInitiator            : IkePayloadType = IkePayloadType(35);
    pub const IdentResponder            : IkePayloadType = IkePayloadType(36);
    pub const Certificate               : IkePayloadType = IkePayloadType(37);
    pub const CertificateRequest        : IkePayloadType = IkePayloadType(38);
    pub const Authentication            : IkePayloadType = IkePayloadType(39);
    pub const Nonce                     : IkePayloadType = IkePayloadType(40);
    pub const Notify                    : IkePayloadType = IkePayloadType(41);
    pub const Delete                    : IkePayloadType = IkePayloadType(42);
    pub const VendorID                  : IkePayloadType = IkePayloadType(43);
    pub const TrafficSelectorInitiator  : IkePayloadType = IkePayloadType(44);
    pub const TrafficSelectorResponder  : IkePayloadType = IkePayloadType(45);
    pub const EncryptedAndAuthenticated : IkePayloadType = IkePayloadType(46);
    pub const Configuration             : IkePayloadType = IkePayloadType(47);
    pub const ExtensibleAuthentication  : IkePayloadType = IkePayloadType(48);
}

impl fmt::Debug for IkePayloadType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            0  => f.write_str("NoNextPayload"),
            33 => f.write_str("SecurityAssociation"),
            34 => f.write_str("KeyExchange"),
            35 => f.write_str("IdentInitiator"),
            36 => f.write_str("IdentResponder"),
            37 => f.write_str("Certificate"),
            38 => f.write_str("CertificateRequest"),
            39 => f.write_str("Authentication"),
            40 => f.write_str("Nonce"),
            41 => f.write_str("Notify"),
            42 => f.write_str("Delete"),
            43 => f.write_str("VendorID"),
            44 => f.write_str("TrafficSelectorInitiator"),
            45 => f.write_str("TrafficSelectorResponder"),
            46 => f.write_str("EncryptedAndAuthenticated"),
            47 => f.write_str("Configuration"),
            48 => f.write_str("ExtensibleAuthentication"),
            n  => f.debug_tuple("IkePayloadType").field(&n).finish(),
        }
    }
}

/// Generic (unparsed payload)
///
/// Defined in [RFC7296]
#[derive(Debug,PartialEq)]
pub struct IkeV2GenericPayload<'a> {
    pub hdr: IkeV2PayloadHeader,
    pub payload: &'a[u8],
}

/// Ciphersuite Proposal
///
/// The Proposal structure contains within it a Proposal Num and an IPsec
/// protocol ID.  Each structure MUST have a proposal number one (1)
/// greater than the previous structure.  The first Proposal in the
/// initiator's SA payload MUST have a Proposal Num of one (1).  One
/// reason to use multiple proposals is to propose both standard crypto
/// ciphers and combined-mode ciphers.  Combined-mode ciphers include
/// both integrity and encryption in a single encryption algorithm, and
/// MUST either offer no integrity algorithm or a single integrity
/// algorithm of "NONE", with no integrity algorithm being the
/// RECOMMENDED method.  If an initiator wants to propose both combined-
/// mode ciphers and normal ciphers, it must include two proposals: one
/// will have all the combined-mode ciphers, and the other will have all
/// the normal ciphers with the integrity algorithms.  For example, one
/// such proposal would have two proposal structures.  Proposal 1 is ESP
/// with AES-128, AES-192, and AES-256 bits in Cipher Block Chaining
/// (CBC) mode, with either HMAC-SHA1-96 or XCBC-96 as the integrity
/// algorithm; Proposal 2 is AES-128 or AES-256 in GCM mode with an
/// 8-octet Integrity Check Value (ICV).  Both proposals allow but do not
/// require the use of ESNs (Extended Sequence Numbers).  This can be
/// illustrated as:
///
/// ```ignore
/// SA Payload
///    |
///    +--- Proposal #1 ( Proto ID = ESP(3), SPI size = 4,
///    |     |            7 transforms,      SPI = 0x052357bb )
///    |     |
///    |     +-- Transform ENCR ( Name = ENCR_AES_CBC )
///    |     |     +-- Attribute ( Key Length = 128 )
///    |     |
///    |     +-- Transform ENCR ( Name = ENCR_AES_CBC )
///    |     |     +-- Attribute ( Key Length = 192 )
///    |     |
///    |     +-- Transform ENCR ( Name = ENCR_AES_CBC )
///    |     |     +-- Attribute ( Key Length = 256 )
///    |     |
///    |     +-- Transform INTEG ( Name = AUTH_HMAC_SHA1_96 )
///    |     +-- Transform INTEG ( Name = AUTH_AES_XCBC_96 )
///    |     +-- Transform ESN ( Name = ESNs )
///    |     +-- Transform ESN ( Name = No ESNs )
///    |
///    +--- Proposal #2 ( Proto ID = ESP(3), SPI size = 4,
///          |            4 transforms,      SPI = 0x35a1d6f2 )
///          |
///          +-- Transform ENCR ( Name = AES-GCM with a 8 octet ICV )
///          |     +-- Attribute ( Key Length = 128 )
///          |
///          +-- Transform ENCR ( Name = AES-GCM with a 8 octet ICV )
///          |     +-- Attribute ( Key Length = 256 )
///          |
///          +-- Transform ESN ( Name = ESNs )
///          +-- Transform ESN ( Name = No ESNs )
/// ```
///
/// Each Proposal/Protocol structure is followed by one or more transform
/// structures.  The number of different transforms is generally
/// determined by the Protocol.  AH generally has two transforms:
/// Extended Sequence Numbers (ESNs) and an integrity check algorithm.
/// ESP generally has three: ESN, an encryption algorithm, and an
/// integrity check algorithm.  IKE generally has four transforms: a
/// Diffie-Hellman group, an integrity check algorithm, a PRF algorithm,
/// and an encryption algorithm.  For each Protocol, the set of
/// permissible transforms is assigned Transform ID numbers, which appear
/// in the header of each transform.
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3.1
#[derive(Clone,Debug,PartialEq)]
pub struct IkeV2Proposal<'a> {
    pub last: u8,
    pub reserved: u8,
    pub proposal_length: u16,
    pub proposal_num: u8,
    pub protocol_id: ProtocolID,
    pub spi_size: u8,
    pub num_transforms: u8,
    pub spi: Option<&'a[u8]>,
    pub transforms: Vec<IkeV2RawTransform<'a>>,
}

/// Key Exchange Payload
///
/// The Key Exchange payload, denoted KE in this document, is used to
/// exchange Diffie-Hellman public numbers as part of a Diffie-Hellman
/// key exchange.  The Key Exchange payload consists of the IKE generic
/// payload header followed by the Diffie-Hellman public value itself.
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.4
#[derive(Debug,PartialEq)]
pub struct KeyExchangePayload<'a> {
    pub dh_group: IkeTransformDHType,
    pub reserved: u16,
    pub kex_data: &'a[u8],
}

/// Identification Payloads
///
/// The Identification payloads, denoted IDi and IDr in this document,
/// allow peers to assert an identity to one another.  This identity may
/// be used for policy lookup, but does not necessarily have to match
/// anything in the CERT payload; both fields may be used by an
/// implementation to perform access control decisions.  When using the
/// ID_IPV4_ADDR/ID_IPV6_ADDR identity types in IDi/IDr payloads, IKEv2
/// does not require this address to match the address in the IP header
/// of IKEv2 packets, or anything in the TSi/TSr payloads.  The contents
/// of IDi/IDr are used purely to fetch the policy and authentication
/// data related to the other party.
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.5
#[derive(Debug,PartialEq)]
pub struct IdentificationPayload<'a> {
    pub id_type: IdentificationType,
    pub reserved1: u8,
    pub reserved2: u16,
    pub ident_data: &'a[u8],
}

/// Type of Identification
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentificationType(pub u8);

impl IdentificationType {
    /// A single four (4) octet IPv4 address.
    pub const ID_IPV4_ADDR   : IdentificationType = IdentificationType(1);
    /// A fully-qualified domain name string.  An example of an ID_FQDN
    /// is "example.com".  The string MUST NOT contain any terminators
    /// (e.g., NULL, CR, etc.).  All characters in the ID_FQDN are ASCII;
    /// for an "internationalized domain name", the syntax is as defined
    /// in [IDNA], for example "xn--tmonesimerkki-bfbb.example.net".
    pub const ID_FQDN        : IdentificationType = IdentificationType(2);
    /// A fully-qualified RFC 822 email address string.  An example of a
    /// ID_RFC822_ADDR is "jsmith@example.com".  The string MUST NOT
    /// contain any terminators.  Because of [EAI], implementations would
    /// be wise to treat this field as UTF-8 encoded text, not as
    /// pure ASCII.
    pub const ID_RFC822_ADDR : IdentificationType = IdentificationType(3);
    /// A single sixteen (16) octet IPv6 address.
    pub const ID_IPV6_ADDR   : IdentificationType = IdentificationType(5);
    /// The binary Distinguished Encoding Rules (DER) encoding of an ASN.1 X.500 Distinguished
    /// Name.
    pub const ID_DER_ASN1_DN : IdentificationType = IdentificationType(9);
    /// The binary DER encoding of an ASN.1 X.509 GeneralName.
    pub const ID_DER_ASN1_GN : IdentificationType = IdentificationType(10);
    /// An opaque octet stream that may be used to pass vendor-specific information necessary to do
    /// certain proprietary types of identification.
    pub const ID_KEY_ID      : IdentificationType = IdentificationType(11);
}

/// Certificate Payload
///
/// The Certificate payload, denoted CERT in this document, provides a
/// means to transport certificates or other authentication-related
/// information via IKE.  Certificate payloads SHOULD be included in an
/// exchange if certificates are available to the sender.  The Hash and
/// URL formats of the Certificate payloads should be used in case the
/// peer has indicated an ability to retrieve this information from
/// elsewhere using an HTTP_CERT_LOOKUP_SUPPORTED Notify payload.  Note
/// that the term "Certificate payload" is somewhat misleading, because
/// not all authentication mechanisms use certificates and data other
/// than certificates may be passed in this payload.
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.6
#[derive(Debug,PartialEq)]
pub struct CertificatePayload<'a> {
    pub cert_encoding: CertificateEncoding,
    pub cert_data: &'a[u8],
}

/// Certificate Encoding
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.6
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateEncoding(pub u8);

#[allow(non_upper_case_globals)]
impl CertificateEncoding {
    /// PKCS #7 wrapped X.509 certificate
    pub const Pkcs7_X509                  : CertificateEncoding = CertificateEncoding(1);
    /// PGP Certificate
    pub const PgpCert                     : CertificateEncoding = CertificateEncoding(2);
    /// DNS Signed Key
    pub const DnsKey                      : CertificateEncoding = CertificateEncoding(3);
    /// X.509 Certificate - Signature
    pub const X509Sig                     : CertificateEncoding = CertificateEncoding(4);
    /// Kerberos Token
    pub const Kerberos                    : CertificateEncoding = CertificateEncoding(6);
    /// Certificate Revocation List (CRL)
    pub const Crl                         : CertificateEncoding = CertificateEncoding(7);
    /// Authority Revocation List (ARL)
    pub const Arl                         : CertificateEncoding = CertificateEncoding(8);
    /// SPKI Certificate
    pub const SpkiCert                    : CertificateEncoding = CertificateEncoding(9);
    /// X.509 Certificate - Attribute
    pub const X509CertAttr                : CertificateEncoding = CertificateEncoding(10);
    /// Deprecated (was Raw RSA Key)
    pub const OldRsaKey                   : CertificateEncoding = CertificateEncoding(11);
    /// Hash and URL of X.509 certificate
    pub const X509Cert_HashUrl            : CertificateEncoding = CertificateEncoding(12);
    /// Hash and URL of X.509 bundle
    pub const X509Bundle_HashUrl          : CertificateEncoding = CertificateEncoding(13);
    /// OCSP Content ([RFC4806](https://tools.ietf.org/html/rfc4806))
    pub const OCSPContent                 : CertificateEncoding = CertificateEncoding(14);
    /// Raw Public Key ([RFC7670](https://tools.ietf.org/html/rfc7670))
    pub const RawPublicKey                : CertificateEncoding = CertificateEncoding(15);
}

/// Certificate Request Payload
///
/// The Certificate Request payload, denoted CERTREQ in this document,
/// provides a means to request preferred certificates via IKE and can
/// appear in the IKE_INIT_SA response and/or the IKE_AUTH request.
/// Certificate Request payloads MAY be included in an exchange when the
/// sender needs to get the certificate of the receiver.
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.7
#[derive(Debug,PartialEq)]
pub struct CertificateRequestPayload<'a> {
    pub cert_encoding: CertificateEncoding,
    pub ca_data: &'a[u8],
}

/// Authentication Payload
///
/// The Authentication payload, denoted AUTH in this document, contains
/// data used for authentication purposes.
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.8
#[derive(Debug,PartialEq)]
pub struct AuthenticationPayload<'a> {
    pub auth_method: AuthenticationMethod,
    pub auth_data: &'a[u8],
}

/// Method of authentication used.
///
/// See also [IKEV2IANA](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml) for the latest values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticationMethod(pub u8);

#[allow(non_upper_case_globals)]
impl AuthenticationMethod {
    /// RSA Digital Signature
    pub const RsaSig          : AuthenticationMethod = AuthenticationMethod(1);
    /// Shared Key Message Integrity Code
    pub const SharedKeyMIC    : AuthenticationMethod = AuthenticationMethod(2);
    /// DSS Digital Signature
    pub const DssSig          : AuthenticationMethod = AuthenticationMethod(3);
    /// ECDSA with SHA-256 on the P-256 curve
    pub const EcdsaSha256P256 : AuthenticationMethod = AuthenticationMethod(9);
    /// ECDSA with SHA-384 on the P-384 curve
    pub const EcdsaSha384P384 : AuthenticationMethod = AuthenticationMethod(10);
    /// ECDSA with SHA-512 on the P-512 curve
    pub const EcdsaSha512P512 : AuthenticationMethod = AuthenticationMethod(11);
    /// Generic Secure Password Authentication Method
    pub const GenericPass     : AuthenticationMethod = AuthenticationMethod(12);
    /// NULL Authentication
    pub const Null            : AuthenticationMethod = AuthenticationMethod(13);
    /// Digital Signature
    pub const DigitalSig      : AuthenticationMethod = AuthenticationMethod(14);

    /// Test if value is in unassigned range
    pub fn is_unassigned(&self) -> bool {
        (self.0 >= 4 && self.0 <= 8) ||
        (self.0 >= 15 && self.0 <= 200)
    }

    /// Test if value is in private use range
    pub fn is_private_use(&self) -> bool {
        self.0 >= 201
    }
}


/// Nonce Payload
///
/// The Nonce payload, denoted as Ni and Nr in this document for the
/// initiator's and responder's nonce, respectively, contains random data used to guarantee
/// liveness during an exchange and protect against replay attacks.
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.9
#[derive(PartialEq)]
pub struct NoncePayload<'a> {
    pub nonce_data: &'a[u8],
}

/// Notify Payload
///
/// The Notify payload, denoted N in this document, is used to transmit informational data, such as
/// error conditions and state transitions, to an IKE peer.  A Notify payload may appear in a
/// response message (usually specifying why a request was rejected), in an INFORMATIONAL exchange
/// (to report an error not in an IKE request), or in any other message to indicate sender
/// capabilities or to modify the meaning of the request.
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.10
#[derive(PartialEq)]
pub struct NotifyPayload<'a> {
    pub protocol_id: ProtocolID,
    pub spi_size: u8,
    pub notify_type: NotifyType,
    pub spi: Option<&'a[u8]>,
    pub notify_data: Option<&'a[u8]>,
}

/// Delete Payload
///
/// The Delete payload, denoted D in this document, contains a
/// protocol-specific Security Association identifier that the sender has
/// removed from its Security Association database and is, therefore, no
/// longer valid.  Figure 17 shows the format of the Delete payload.  It
/// is possible to send multiple SPIs in a Delete payload; however, each
/// SPI MUST be for the same protocol.  Mixing of protocol identifiers
/// MUST NOT be performed in the Delete payload.  It is permitted,
/// however, to include multiple Delete payloads in a single
/// INFORMATIONAL exchange where each Delete payload lists SPIs for a
/// different protocol.
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.11
#[derive(Debug,PartialEq)]
pub struct DeletePayload<'a> {
    pub protocol_id: ProtocolID,
    pub spi_size: u8,
    pub num_spi: u16,
    pub spi: &'a[u8],
}

/// Vendor ID Payload
///
/// The Vendor ID payload, denoted V in this document, contains a vendor-
/// defined constant.  The constant is used by vendors to identify and
/// recognize remote instances of their implementations.  This mechanism
/// allows a vendor to experiment with new features while maintaining
/// backward compatibility.
///
/// A Vendor ID payload MAY announce that the sender is capable of
/// accepting certain extensions to the protocol, or it MAY simply
/// identify the implementation as an aid in debugging.  A Vendor ID
/// payload MUST NOT change the interpretation of any information defined
/// in this specification (i.e., the critical bit MUST be set to 0).
/// Multiple Vendor ID payloads MAY be sent.  An implementation is not
/// required to send any Vendor ID payload at all.
///
/// A Vendor ID payload may be sent as part of any message.  Reception of
/// a familiar Vendor ID payload allows an implementation to make use of
/// private use numbers described throughout this document, such as
/// private payloads, private exchanges, private notifications, etc.
/// Unfamiliar Vendor IDs MUST be ignored.
///
/// Writers of documents who wish to extend this protocol MUST define a
/// Vendor ID payload to announce the ability to implement the extension
/// in the document.  It is expected that documents that gain acceptance
/// and are standardized will be given "magic numbers" out of the Future
/// Use range by IANA, and the requirement to use a Vendor ID will go
/// away.
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.12
#[derive(Debug,PartialEq)]
pub struct VendorIDPayload<'a> {
    pub vendor_id: &'a[u8],
}

/// Type of Traffic Selector
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.13.1
///
/// See also [IKEV2IANA](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml) for the latest values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TSType(pub u8);

#[allow(non_upper_case_globals)]
impl TSType {
    /// A range of IPv4 addresses
    pub const IPv4AddrRange : TSType = TSType(7);
    /// A range of IPv6 addresses
    pub const IPv6AddrRange : TSType = TSType(8);
    /// Fibre Channel Traffic Selectors ([RFC4595](https://tools.ietf.org/html/rfc4595))
    pub const FcAddrRange   : TSType = TSType(9);
}

/// Traffic Selector
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.13.1
#[derive(Debug,PartialEq)]
pub struct TrafficSelector<'a> {
    pub ts_type: TSType,
    pub ip_proto_id: u8,
    pub sel_length: u16,
    pub start_port: u16,
    pub end_port: u16,
    pub start_addr: &'a[u8],
    pub end_addr: &'a[u8],
}

fn ipv4_from_slice(b:&[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

fn ipv6_from_slice(b:&[u8]) -> Ipv6Addr {
    Ipv6Addr::new(
        (b[0] as u16) << 8 | (b[1] as u16),
        (b[2] as u16) << 8 | (b[3] as u16),
        (b[4] as u16) << 8 | (b[5] as u16),
        (b[6] as u16) << 8 | (b[7] as u16),
        (b[8] as u16) << 8 | (b[9] as u16),
        (b[10] as u16) << 8 | (b[11] as u16),
        (b[12] as u16) << 8 | (b[13] as u16),
        (b[14] as u16) << 8 | (b[15] as u16),
    )
}

impl<'a> TrafficSelector<'a> {
    pub fn get_ts_type(&self) -> TSType {
        self.ts_type
    }

    pub fn get_start_addr(&self) -> Option<IpAddr> {
        match self.ts_type {
            TSType::IPv4AddrRange => Some(IpAddr::V4(ipv4_from_slice(self.start_addr))),
            TSType::IPv6AddrRange => Some(IpAddr::V6(ipv6_from_slice(self.start_addr))),
            _ => None,
        }
    }

    pub fn get_end_addr(&self) -> Option<IpAddr> {
        match self.ts_type {
            TSType::IPv4AddrRange => Some(IpAddr::V4(ipv4_from_slice(self.end_addr))),
            TSType::IPv6AddrRange => Some(IpAddr::V6(ipv6_from_slice(self.end_addr))),
            _ => None,
        }
    }
}

/// Traffic Selector Payload
///
/// The Traffic Selector payload, denoted TS in this document, allows
/// peers to identify packet flows for processing by IPsec security
/// services.  The Traffic Selector payload consists of the IKE generic
/// payload header followed by individual Traffic Selectors.
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.13
#[derive(Debug,PartialEq)]
pub struct TrafficSelectorPayload<'a> {
    pub num_ts: u8,
    pub reserved: &'a[u8], // 3 bytes
    pub ts: Vec<TrafficSelector<'a>>,
}

/// IKE Message Payload Content
///
/// The content of an IKE message is one of the defined payloads.
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.2
#[derive(Debug,PartialEq)]
pub enum IkeV2PayloadContent<'a> {
    SA(Vec<IkeV2Proposal<'a>>),
    KE(KeyExchangePayload<'a>),
    IDi(IdentificationPayload<'a>),
    IDr(IdentificationPayload<'a>),
    Certificate(CertificatePayload<'a>),
    CertificateRequest(CertificateRequestPayload<'a>),
    Authentication(AuthenticationPayload<'a>),
    Nonce(NoncePayload<'a>),
    Notify(NotifyPayload<'a>),
    Delete(DeletePayload<'a>),
    VendorID(VendorIDPayload<'a>),
    TSi(TrafficSelectorPayload<'a>),
    TSr(TrafficSelectorPayload<'a>),

    Unknown(&'a[u8]),

    Dummy,
}

/// Generic Payload Header
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.2
#[derive(Clone,Debug,PartialEq)]
pub struct IkeV2PayloadHeader {
    pub next_payload_type: IkePayloadType,
    pub critical: bool,
    pub reserved: u8,
    pub payload_length: u16,
}

/// IKE Message Payload
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3
#[derive(Debug,PartialEq)]
pub struct IkeV2Payload<'a> {
    pub hdr: IkeV2PayloadHeader,
    pub content: IkeV2PayloadContent<'a>,
}
