// See https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml

use std::fmt;

/// Address type
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AddressType(pub i32);

impl AddressType {
    pub const IPV4          : AddressType = AddressType(2);
    pub const DIRECTIONAL   : AddressType = AddressType(3);
    pub const CHAOSNET      : AddressType = AddressType(5);
    pub const XNS           : AddressType = AddressType(6);
    pub const ISO           : AddressType = AddressType(7);
    pub const DECNET_P4     : AddressType = AddressType(12);
    pub const APPLETALK_DDP : AddressType = AddressType(16);
    pub const NETBIOS       : AddressType = AddressType(20);
    pub const IPV6          : AddressType = AddressType(24);
}

impl fmt::Debug for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            2  => f.write_str("IPv4"),
            3  => f.write_str("Directional"),
            5  => f.write_str("ChaosNet"),
            6  => f.write_str("XNS"),
            7  => f.write_str("ISO"),
            12 => f.write_str("DECNET Phase IV"),
            16 => f.write_str("Appletalk DDP"),
            20 => f.write_str("Netbios"),
            24 => f.write_str("IPv6"),
            n  => f.debug_tuple("AddressType").field(&n).finish(),
        }
    }
}

/// Encryption type
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EncryptionType(pub i32);

impl EncryptionType {
    pub const DES_CBC_CRC                  : EncryptionType = EncryptionType(1);
    pub const DES_CBC_MD4                  : EncryptionType = EncryptionType(2);
    pub const DES_CBC_MD5                  : EncryptionType = EncryptionType(3);
    pub const DES3_CBC_MD5                 : EncryptionType = EncryptionType(5);
    pub const DES3_CBC_SHA1                : EncryptionType = EncryptionType(7);
    pub const DSAWITHSHA1_CMSOID           : EncryptionType = EncryptionType(9);
    pub const MD5WITHRSAENCRYPTION_CMSOID  : EncryptionType = EncryptionType(10);
    pub const SHA1WITHRSAENCRYPTION_CMSOID : EncryptionType = EncryptionType(11);
    pub const RC2CBC_ENVOID                : EncryptionType = EncryptionType(12);
    pub const RSAENCRYPTION_ENVOID         : EncryptionType = EncryptionType(13);
    pub const RSAES_OAEP_ENV_OID           : EncryptionType = EncryptionType(14);
    pub const DES_EDE3_CBC_ENV_OID         : EncryptionType = EncryptionType(15);
    pub const DES3_CBC_SHA1_KD             : EncryptionType = EncryptionType(16);
    pub const AES128_CTS_HMAC_SHA1_96      : EncryptionType = EncryptionType(17);
    pub const AES256_CTS_HMAC_SHA1_96      : EncryptionType = EncryptionType(18);
    pub const AES128_CTS_HMAC_SHA256_128   : EncryptionType = EncryptionType(19);
    pub const AES256_CTS_HMAC_SHA384_192   : EncryptionType = EncryptionType(20);
    pub const RC4_HMAC                     : EncryptionType = EncryptionType(23);
    pub const RC4_HMAC_EXP                 : EncryptionType = EncryptionType(24);
    pub const CAMELLIA128_CTS_CMAC         : EncryptionType = EncryptionType(25);
    pub const CAMELLIA256_CTS_CMAC         : EncryptionType = EncryptionType(26);
    pub const SUBKEY_KEYMATERIAL           : EncryptionType = EncryptionType(65);
    // negative values
    pub const RC4_MD4                      : EncryptionType = EncryptionType(-128);
    pub const RC4_PLAIN2                   : EncryptionType = EncryptionType(-129);
    pub const RC4_LM                       : EncryptionType = EncryptionType(-130);
    pub const RC4_SHA                      : EncryptionType = EncryptionType(-131);
    pub const DES_PLAIN                    : EncryptionType = EncryptionType(-132);
    pub const RC4_HMAC_OLD                 : EncryptionType = EncryptionType(-133);
    pub const RC4_PLAIN_OLD                : EncryptionType = EncryptionType(-134);
    pub const RC4_HMAC_OLD_EXP             : EncryptionType = EncryptionType(-135);
    pub const RC4_PLAIN_OLD_EXP            : EncryptionType = EncryptionType(-136);
    pub const RC4_PLAIN                    : EncryptionType = EncryptionType(-140);
    pub const RC4_PLAIN_EXP                : EncryptionType = EncryptionType(-141);
}

impl fmt::Debug for EncryptionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            1    => f.write_str("des-cbc-crc"),
            2    => f.write_str("des-cbc-md4"),
            3    => f.write_str("des-cbc-md5"),
            5    => f.write_str("des3-cbc-md5"),
            7    => f.write_str("des3-cbc-sha1"),
            9    => f.write_str("dsaWithSHA1-CmsOID"),
            10   => f.write_str("md5WithRSAEncryption-CmsOID"),
            11   => f.write_str("sha1WithRSAEncryption-CmsOID"),
            12   => f.write_str("rc2CBC-EnvOID"),
            13   => f.write_str("rsaEncryption-EnvOID"),
            14   => f.write_str("rsaES-OAEP-ENV-OID"),
            15   => f.write_str("des-ede3-cbc-Env-OID"),
            16   => f.write_str("des3-cbc-sha1-kd"),
            17   => f.write_str("aes128-cts-hmac-sha1-96"),
            18   => f.write_str("aes256-cts-hmac-sha1-96"),
            19   => f.write_str("aes128-cts-hmac-sha256-128"),
            20   => f.write_str("aes256-cts-hmac-sha384-192"),
            23   => f.write_str("rc4-hmac"),
            24   => f.write_str("rc4-hmac-exp"),
            25   => f.write_str("camellia128-cts-cmac"),
            26   => f.write_str("camellia256-cts-cmac"),
            65   => f.write_str("subkey-keymaterial"),
            // negative values
            -128 => f.write_str("rc4-md4"),
            -129 => f.write_str("rc4-plain2"),
            -130 => f.write_str("rc4-lm"),
            -131 => f.write_str("rc4-sha"),
            -132 => f.write_str("des-plain"),
            -133 => f.write_str("rc4-hmac-OLD"),
            -134 => f.write_str("rc4-plain-OLD"),
            -135 => f.write_str("rc4-hmac-OLD-exp"),
            -136 => f.write_str("rc4-plain-OLD-exp"),
            -140 => f.write_str("rc4-plain"),
            -141 => f.write_str("rc4-plain-exp"),
            n    => f.debug_tuple("EncryptionType").field(&n).finish(),
        }
    }
}

/// Message type
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MessageType(pub u32);

impl MessageType {
    /// Request for initial authentication
    pub const KRB_AS_REQ     : MessageType = MessageType(10);
    /// Response to KRB_AS_REQ request
    pub const KRB_AS_REP     : MessageType = MessageType(11);
    /// Request for authentication based on TGT
    pub const KRB_TGS_REQ    : MessageType = MessageType(12);
    /// Response to KRB_TGS_REQ request
    pub const KRB_TGS_REP    : MessageType = MessageType(13);
    /// Application request to server
    pub const KRB_AP_REQ     : MessageType = MessageType(14);
    /// Response to KRB_AP_REQ_MUTUAL
    pub const KRB_AP_REP     : MessageType = MessageType(15);
    /// Reserved for user-to-user krb_tgt_request
    pub const KRB_RESERVED16 : MessageType = MessageType(16);
    /// Reserved for user-to-user krb_tgt_reply
    pub const KRB_RESERVED17 : MessageType = MessageType(17);
    /// Safe (checksummed) application message
    pub const KRB_SAFE       : MessageType = MessageType(20);
    /// Private (encrypted) application message
    pub const KRB_PRIV       : MessageType = MessageType(21);
    /// Private (encrypted) message to forward credentials
    pub const KRB_CRED       : MessageType = MessageType(22);
    /// Error response
    pub const KRB_ERROR      : MessageType = MessageType(30);
}

impl fmt::Debug for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            10 => f.write_str("KRB_AS_REQ"),
            11 => f.write_str("KRB_AS_REP"),
            12 => f.write_str("KRB_TGS_REQ"),
            13 => f.write_str("KRB_TGS_REP"),
            14 => f.write_str("KRB_AP_REQ"),
            15 => f.write_str("KRB_AP_REP"),
            16 => f.write_str("KRB_RESERVED16"),
            17 => f.write_str("KRB_RESERVED17"),
            20 => f.write_str("KRB_SAFE"),
            21 => f.write_str("KRB_PRIV"),
            22 => f.write_str("KRB_CRED"),
            30 => f.write_str("KRB_ERROR"),
            n  => f.debug_tuple("MessageType").field(&n).finish(),
        }
    }
}


/// Name type
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NameType(pub i32);

impl NameType {
    /// Name type not known
    pub const KRB_NT_UNKNOWN        : NameType = NameType(0);
    /// Just the name of the principal as in DCE, or for users
    pub const KRB_NT_PRINCIPAL      : NameType = NameType(1);
    /// Service and other unique instance (krbtgt)
    pub const KRB_NT_SRV_INST       : NameType = NameType(2);
    /// Service with host name as instance (telnet, rcommands)
    pub const KRB_NT_SRV_HST        : NameType = NameType(3);
    /// Service with host as remaining components
    pub const KRB_NT_SRV_XHST       : NameType = NameType(4);
    /// Unique ID
    pub const KRB_NT_UID            : NameType = NameType(5);
    /// Encoded X.509 Distinguished name [RFC2253]
    pub const KRB_NT_X500_PRINCIPAL : NameType = NameType(6);
    /// Name in form of SMTP email name (e.g., user@example.com)
    pub const KRB_NT_SMTP_NAME      : NameType = NameType(7);
    /// Enterprise name; may be mapped to principal name
    pub const KRB_NT_ENTERPRISE     : NameType = NameType(10);
}

impl fmt::Debug for NameType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            0  => f.write_str("KRB_NT_UNKNOWN"),
            1  => f.write_str("KRB_NT_PRINCIPAL"),
            2  => f.write_str("KRB_NT_SRV_INST"),
            3  => f.write_str("KRB_NT_SRV_HST"),
            4  => f.write_str("KRB_NT_SRV_XHST"),
            5  => f.write_str("KRB_NT_UID"),
            6  => f.write_str("KRB_NT_X500_PRINCIPAL"),
            7  => f.write_str("KRB_NT_SMTP_NAME"),
            10 => f.write_str("KRB_NT_ENTERPRISE"),
            n  => f.debug_tuple("NameType").field(&n).finish(),
        }
    }
}

/// PA-Data type
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PAType(pub i32);

impl PAType {
    /// DER encoding of AP-REQ
    pub const PA_TGS_REQ          : PAType = PAType(1);
    /// DER encoding of PA-ENC-TIMESTAMP
    pub const PA_ENC_TS           : PAType = PAType(2);
    /// salt (not ASN.1 encoded)
    pub const PA_PW_SALT          : PAType = PAType(3);
    /// DER encoding of ETYPE-INFO
    pub const PA_ETYPE_INFO       : PAType = PAType(11);
    /// DER encoding of ETYPE-INFO2
    pub const PA_ETYPE_INFO2      : PAType = PAType(19);
    /// Windows PAC request
    pub const PA_PAC_REQUEST      : PAType = PAType(128);
    /// Support for FAST pre-auth mechanism
    pub const PA_REQ_ENC_PA_REP   : PAType = PAType(149);
}

impl fmt::Debug for PAType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            1   => f.write_str("pa-tgs-req"),
            2   => f.write_str("pa-enc-timestamp"),
            3   => f.write_str("pa-pw-salt"),
            11  => f.write_str("pa-etype-info"),
            19  => f.write_str("pa-etype-info2"),
            128 => f.write_str("pa-pac-request"),
            149 => f.write_str("pa-req-enc-pa-rep"),
            n   => f.debug_tuple("PAType").field(&n).finish(),
        }
    }
}
