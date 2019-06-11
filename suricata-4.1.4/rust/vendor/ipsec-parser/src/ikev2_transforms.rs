use std::convert::From;
use std::fmt;

/// Transform (cryptographic algorithm) type
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3.2
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IkeTransformType(pub u8);

#[allow(non_upper_case_globals)]
impl IkeTransformType {
    pub const EncryptionAlgorithm     : IkeTransformType = IkeTransformType(1);
    pub const PseudoRandomFunction    : IkeTransformType = IkeTransformType(2);
    pub const IntegrityAlgorithm      : IkeTransformType = IkeTransformType(3);
    pub const DiffieHellmanGroup      : IkeTransformType = IkeTransformType(4);
    pub const ExtendedSequenceNumbers : IkeTransformType = IkeTransformType(5);
}


/// Encryption values
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3.2
///
/// See also [IKEV2IANA](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml) for the latest values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IkeTransformEncType(pub u16);

impl IkeTransformEncType {
    // 0 is reserved
    pub const ENCR_DES_IV64           : IkeTransformEncType = IkeTransformEncType(1);
    pub const ENCR_DES                : IkeTransformEncType = IkeTransformEncType(2);
    pub const ENCR_3DES               : IkeTransformEncType = IkeTransformEncType(3);
    pub const ENCR_RC5                : IkeTransformEncType = IkeTransformEncType(4);
    pub const ENCR_IDEA               : IkeTransformEncType = IkeTransformEncType(5);
    pub const ENCR_CAST               : IkeTransformEncType = IkeTransformEncType(6);
    pub const ENCR_BLOWFISH           : IkeTransformEncType = IkeTransformEncType(7);
    pub const ENCR_3IDEA              : IkeTransformEncType = IkeTransformEncType(8);
    pub const ENCR_DES_IV32           : IkeTransformEncType = IkeTransformEncType(9);
    // 10 is reserved
    pub const ENCR_NULL               : IkeTransformEncType = IkeTransformEncType(11);
    pub const ENCR_AES_CBC            : IkeTransformEncType = IkeTransformEncType(12);
    pub const ENCR_AES_CTR            : IkeTransformEncType = IkeTransformEncType(13);
    pub const ENCR_AES_CCM_8          : IkeTransformEncType = IkeTransformEncType(14);
    pub const ENCR_AES_CCM_12         : IkeTransformEncType = IkeTransformEncType(15);
    pub const ENCR_AES_CCM_16         : IkeTransformEncType = IkeTransformEncType(16);
    // 17 is unassigned
    pub const ENCR_AES_GCM_8          : IkeTransformEncType = IkeTransformEncType(18);
    pub const ENCR_AES_GCM_12         : IkeTransformEncType = IkeTransformEncType(19);
    pub const ENCR_AES_GCM_16         : IkeTransformEncType = IkeTransformEncType(20);
    pub const ENCR_NULL_AUTH_AES_GMAC : IkeTransformEncType = IkeTransformEncType(21);
    // 22 is reserved for IEEE P1619 XTS-AES
    pub const ENCR_CAMELLIA_CBC       : IkeTransformEncType = IkeTransformEncType(23);
    pub const ENCR_CAMELLIA_CTR       : IkeTransformEncType = IkeTransformEncType(24);
    pub const ENCR_CAMELLIA_CCM_8     : IkeTransformEncType = IkeTransformEncType(25);
    pub const ENCR_CAMELLIA_CCM_12    : IkeTransformEncType = IkeTransformEncType(26);
    pub const ENCR_CAMELLIA_CCM_16    : IkeTransformEncType = IkeTransformEncType(27);
    pub const ENCR_CHACHA20_POLY1305  : IkeTransformEncType = IkeTransformEncType(28); // [RFC7634]
}

impl IkeTransformEncType {
    pub fn is_aead(&self) -> bool {
        match *self {
            IkeTransformEncType::ENCR_AES_CCM_8 |
            IkeTransformEncType::ENCR_AES_CCM_12 |
            IkeTransformEncType::ENCR_AES_CCM_16 |
            IkeTransformEncType::ENCR_AES_GCM_8 |
            IkeTransformEncType::ENCR_AES_GCM_12 |
            IkeTransformEncType::ENCR_AES_GCM_16 |
            IkeTransformEncType::ENCR_CAMELLIA_CCM_8 |
            IkeTransformEncType::ENCR_CAMELLIA_CCM_12 |
            IkeTransformEncType::ENCR_CAMELLIA_CCM_16 |
            IkeTransformEncType::ENCR_CHACHA20_POLY1305 => true,
            _ => false,
        }
    }

    pub fn is_unassigned(&self) -> bool { self.0 >= 23 && self.0 <= 1023 }
    pub fn is_private_use(&self) -> bool { self.0 >= 1024 }
}

/// Pseudo-Random Function values
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3.2
///
/// See also [IKEV2IANA](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml) for the latest values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IkeTransformPRFType(pub u16);

impl IkeTransformPRFType {
    pub const PRF_NULL          : IkeTransformPRFType = IkeTransformPRFType(0);
    pub const PRF_HMAC_MD5      : IkeTransformPRFType = IkeTransformPRFType(1);
    pub const PRF_HMAC_SHA1     : IkeTransformPRFType = IkeTransformPRFType(2);
    pub const PRF_HMAC_TIGER    : IkeTransformPRFType = IkeTransformPRFType(3);
    pub const PRF_AES128_XCBC   : IkeTransformPRFType = IkeTransformPRFType(4);
    pub const PRF_HMAC_SHA2_256 : IkeTransformPRFType = IkeTransformPRFType(5);
    pub const PRF_HMAC_SHA2_384 : IkeTransformPRFType = IkeTransformPRFType(6);
    pub const PRF_HMAC_SHA2_512 : IkeTransformPRFType = IkeTransformPRFType(7);
    pub const PRF_AES128_CMAC   : IkeTransformPRFType = IkeTransformPRFType(8);

    pub fn is_unassigned(&self) -> bool { self.0 >= 9 && self.0 <= 1023 }
    pub fn is_private_use(&self) -> bool { self.0 >= 1024 }
}

/// Authentication / Integrity values
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3.2
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IkeTransformAuthType(pub u16);

impl IkeTransformAuthType {
    pub const NONE                   : IkeTransformAuthType = IkeTransformAuthType(0);
    pub const AUTH_HMAC_MD5_96       : IkeTransformAuthType = IkeTransformAuthType(1);
    pub const AUTH_HMAC_SHA1_96      : IkeTransformAuthType = IkeTransformAuthType(2);
    pub const AUTH_DES_MAC           : IkeTransformAuthType = IkeTransformAuthType(3);
    pub const AUTH_KPDK_MD5          : IkeTransformAuthType = IkeTransformAuthType(4);
    pub const AUTH_AES_XCBC_96       : IkeTransformAuthType = IkeTransformAuthType(5);
    pub const AUTH_HMAC_MD5_128      : IkeTransformAuthType = IkeTransformAuthType(6);
    pub const AUTH_HMAC_SHA1_160     : IkeTransformAuthType = IkeTransformAuthType(7);
    pub const AUTH_AES_CMAC_96       : IkeTransformAuthType = IkeTransformAuthType(8);
    pub const AUTH_AES_128_GMAC      : IkeTransformAuthType = IkeTransformAuthType(9);
    pub const AUTH_AES_192_GMAC      : IkeTransformAuthType = IkeTransformAuthType(10);
    pub const AUTH_AES_256_GMAC      : IkeTransformAuthType = IkeTransformAuthType(11);
    pub const AUTH_HMAC_SHA2_256_128 : IkeTransformAuthType = IkeTransformAuthType(12);
    pub const AUTH_HMAC_SHA2_384_192 : IkeTransformAuthType = IkeTransformAuthType(13);
    pub const AUTH_HMAC_SHA2_512_256 : IkeTransformAuthType = IkeTransformAuthType(14);

    pub fn is_unassigned(&self) -> bool { self.0 >= 15 && self.0 <= 1023 }
    pub fn is_private_use(&self) -> bool { self.0 >= 1024 }
}

/// Diffie-Hellman values
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3.2
///
/// See also [IKEV2IANA](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml) for the latest values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IkeTransformDHType(pub u16);

#[allow(non_upper_case_globals)]
impl IkeTransformDHType {
    pub const None            : IkeTransformDHType = IkeTransformDHType(0);
    pub const Modp768         : IkeTransformDHType = IkeTransformDHType(1);
    pub const Modp1024        : IkeTransformDHType = IkeTransformDHType(2);
    pub const Modp1536        : IkeTransformDHType = IkeTransformDHType(5);
    pub const Modp2048        : IkeTransformDHType = IkeTransformDHType(14);
    pub const Modp3072        : IkeTransformDHType = IkeTransformDHType(15);
    pub const Modp4096        : IkeTransformDHType = IkeTransformDHType(16);
    pub const Modp6144        : IkeTransformDHType = IkeTransformDHType(17);
    pub const Modp8192        : IkeTransformDHType = IkeTransformDHType(18);
    pub const Ecp256          : IkeTransformDHType = IkeTransformDHType(19);
    pub const Ecp384          : IkeTransformDHType = IkeTransformDHType(20);
    pub const Ecp521          : IkeTransformDHType = IkeTransformDHType(21);
    pub const Modp1024s160    : IkeTransformDHType = IkeTransformDHType(22);
    pub const Modp2048s224    : IkeTransformDHType = IkeTransformDHType(23);
    pub const Modp2048s256    : IkeTransformDHType = IkeTransformDHType(24);
    pub const Ecp192          : IkeTransformDHType = IkeTransformDHType(25);
    pub const Ecp224          : IkeTransformDHType = IkeTransformDHType(26);
    pub const BrainpoolP224r1 : IkeTransformDHType = IkeTransformDHType(27);
    pub const BrainpoolP256r1 : IkeTransformDHType = IkeTransformDHType(28);
    pub const BrainpoolP384r1 : IkeTransformDHType = IkeTransformDHType(29);
    pub const BrainpoolP512r1 : IkeTransformDHType = IkeTransformDHType(30);
    pub const Curve25519      : IkeTransformDHType = IkeTransformDHType(31);
    pub const Curve448        : IkeTransformDHType = IkeTransformDHType(32);

    pub fn is_unassigned(&self) -> bool { self.0 >= 15 && self.0 <= 1023 }
    pub fn is_private_use(&self) -> bool { self.0 >= 1024 }
}

/// Extended Sequence Number values
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3.2
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IkeTransformESNType(pub u16);

#[allow(non_upper_case_globals)]
impl IkeTransformESNType {
    pub const NoESN : IkeTransformESNType = IkeTransformESNType(0);
    pub const ESN   : IkeTransformESNType = IkeTransformESNType(1);
}

/// Raw representation of a transform (cryptographic algorithm) and parameters
///
/// Use the `From` method to convert it to a [`IkeV2Transform`](enum.IkeV2Transform.html)
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3
#[derive(Clone,PartialEq)]
pub struct IkeV2RawTransform<'a> {
    pub last: u8,
    pub reserved1: u8,
    pub transform_length: u16,
    pub transform_type: IkeTransformType,
    pub reserved2: u8,
    pub transform_id: u16,
    pub attributes: Option<&'a[u8]>,
}

/// IKEv2 Transform (cryptographic algorithm)
///
/// This structure is a simple representation of a transform, containing only the type (encryption,
/// etc.). To store the parameters, use [`IkeV2RawTransform`](struct.IkeV2RawTransform.html).
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3
#[derive(Debug,PartialEq)]
pub enum IkeV2Transform {
    Encryption(IkeTransformEncType),
    PRF(IkeTransformPRFType),
    Auth(IkeTransformAuthType),
    DH(IkeTransformDHType),
    ESN(IkeTransformESNType),
    /// Unknown tranform (type,id)
    Unknown(IkeTransformType,u16),
}

impl<'a> From<&'a IkeV2RawTransform<'a>> for IkeV2Transform {
    fn from(r: &IkeV2RawTransform) -> IkeV2Transform {
        match r.transform_type {
            IkeTransformType::EncryptionAlgorithm => {
                IkeV2Transform::Encryption(IkeTransformEncType(r.transform_id))
            },
            IkeTransformType::PseudoRandomFunction => {
                IkeV2Transform::PRF(IkeTransformPRFType(r.transform_id))
            },
            IkeTransformType::IntegrityAlgorithm => {
                IkeV2Transform::Auth(IkeTransformAuthType(r.transform_id))
            },
            IkeTransformType::DiffieHellmanGroup => {
                IkeV2Transform::DH(IkeTransformDHType(r.transform_id))
            },
            IkeTransformType::ExtendedSequenceNumbers => {
                IkeV2Transform::ESN(IkeTransformESNType(r.transform_id))
            },
            _ => IkeV2Transform::Unknown(r.transform_type,r.transform_id)
        }
    }
}

impl<'a> From<IkeV2RawTransform<'a>> for IkeV2Transform {
    fn from(r: IkeV2RawTransform) -> IkeV2Transform {
        (&r).into()
    }
}

impl fmt::Debug for IkeTransformType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            1 => f.write_str("EncryptionAlgorithm"),
            2 => f.write_str("PseudoRandomFunction"),
            3 => f.write_str("IntegrityAlgorithm"),
            4 => f.write_str("DiffieHellmanGroup"),
            5 => f.write_str("ExtendedSequenceNumbers"),
            n => f.debug_tuple("IkeTransformType").field(&n).finish(),
        }
    }
}

impl fmt::Debug for IkeTransformEncType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            1  => f.write_str("ENCR_DES_IV64"),
            2  => f.write_str("ENCR_DES"),
            3  => f.write_str("ENCR_3DES"),
            4  => f.write_str("ENCR_RC5"),
            5  => f.write_str("ENCR_IDEA"),
            6  => f.write_str("ENCR_CAST"),
            7  => f.write_str("ENCR_BLOWFISH"),
            8  => f.write_str("ENCR_3IDEA"),
            9  => f.write_str("ENCR_DES_IV32"),
            11 => f.write_str("ENCR_NULL"),
            12 => f.write_str("ENCR_AES_CBC"),
            13 => f.write_str("ENCR_AES_CTR"),
            14 => f.write_str("ENCR_AES_CCM_8"),
            15 => f.write_str("ENCR_AES_CCM_12"),
            16 => f.write_str("ENCR_AES_CCM_16"),
            18 => f.write_str("ENCR_AES_GCM_8"),
            19 => f.write_str("ENCR_AES_GCM_12"),
            20 => f.write_str("ENCR_AES_GCM_16"),
            21 => f.write_str("ENCR_NULL_AUTH_AES_GMAC"),
            23 => f.write_str("ENCR_CAMELLIA_CBC"),
            24 => f.write_str("ENCR_CAMELLIA_CTR"),
            25 => f.write_str("ENCR_CAMELLIA_CCM_8"),
            26 => f.write_str("ENCR_CAMELLIA_CCM_12"),
            27 => f.write_str("ENCR_CAMELLIA_CCM_16"),
            28 => f.write_str("ENCR_CHACHA20_POLY1305"),
            n  => f.debug_tuple("IkeTransformEncType").field(&n).finish(),
        }
    }
}

impl fmt::Debug for IkeTransformPRFType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            0  => f.write_str("Null"),
            1  => f.write_str("PRF_HMAC_MD5"),
            2  => f.write_str("PRF_HMAC_SHA1"),
            3  => f.write_str("PRF_HMAC_TIGER"),
            4  => f.write_str("PRF_AES128_XCBC"),
            5  => f.write_str("PRF_HMAC_SHA2_256"),
            6  => f.write_str("PRF_HMAC_SHA2_384"),
            7  => f.write_str("PRF_HMAC_SHA2_512"),
            8  => f.write_str("PRF_AES128_CMAC"),
            n  => f.debug_tuple("IkeTransformPRFType").field(&n).finish(),
        }
    }
}

impl fmt::Debug for IkeTransformAuthType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            0  => f.write_str("NONE"),
            1  => f.write_str("AUTH_HMAC_MD5_96"),
            2  => f.write_str("AUTH_HMAC_SHA1_96"),
            3  => f.write_str("AUTH_DES_MAC"),
            4  => f.write_str("AUTH_KPDK_MD5"),
            5  => f.write_str("AUTH_AES_XCBC_96"),
            6  => f.write_str("AUTH_HMAC_MD5_128"),
            7  => f.write_str("AUTH_HMAC_SHA1_128"),
            8  => f.write_str("AUTH_AES_CMAC_96"),
            9  => f.write_str("AUTH_AES_128_GMAC"),
            10 => f.write_str("AUTH_AES_192_GMAC"),
            11 => f.write_str("AUTH_AES_256_GMAC"),
            12 => f.write_str("AUTH_HMAC_SHA2_256_128"),
            13 => f.write_str("AUTH_HMAC_SHA2_384_192"),
            14 => f.write_str("AUTH_HMAC_SHA2_512_256"),
            n  => f.debug_tuple("IkeTransformAuthType").field(&n).finish(),
        }
    }
}

impl fmt::Debug for IkeTransformDHType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            0  => f.write_str("None"),
            1  => f.write_str("768-bit MODP Group"),
            2  => f.write_str("1024-bit MODP Group"),
            5  => f.write_str("1536-bit MODP Group"),
            14 => f.write_str("2048-bit MODP Group"),
            15 => f.write_str("3072-bit MODP Group"),
            16 => f.write_str("4096-bit MODP Group"),
            17 => f.write_str("6144-bit MODP Group"),
            18 => f.write_str("8192-bit MODP Group"),
            19 => f.write_str("256-bit random ECP group"),
            20 => f.write_str("384-bit random ECP group"),
            21 => f.write_str("521-bit random ECP group"),
            22 => f.write_str("1024-bit MODP Group with 160-bit Prime Order Subgroup"),
            23 => f.write_str("2048-bit MODP Group with 224-bit Prime Order Subgroup"),
            24 => f.write_str("2048-bit MODP Group with 256-bit Prime Order Subgroup"),
            25 => f.write_str("192-bit Random ECP Group"),
            26 => f.write_str("224-bit Random ECP Group"),
            27 => f.write_str("brainpoolP224r1"),
            28 => f.write_str("brainpoolP256r1"),
            29 => f.write_str("brainpoolP384r1"),
            30 => f.write_str("brainpoolP512r1"),
            31 => f.write_str("Curve25519"),
            32 => f.write_str("Curve448"),
            n  => f.debug_tuple("IkeTransformDHType").field(&n).finish(),
        }
    }
}

impl fmt::Debug for IkeTransformESNType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            0 => f.write_str("NoESN"),
            1 => f.write_str("ESN"),
            n => f.debug_tuple("IkeTransformESNType").field(&n).finish(),
        }
    }
}
