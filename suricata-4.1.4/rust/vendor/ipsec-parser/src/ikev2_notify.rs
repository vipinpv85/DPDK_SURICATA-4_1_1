use std::fmt;

/// Notify Message Type
///
/// Notification information can be error messages specifying why an SA
/// could not be established.  It can also be status data that a process
/// managing an SA database wishes to communicate with a peer process.
///
/// The table below lists the notification messages and their
/// corresponding values.  The number of different error statuses was
/// greatly reduced from IKEv1 both for simplification and to avoid
/// giving configuration information to probers.
///
/// Types in the range 0 - 16383 are intended for reporting errors.  An
/// implementation receiving a Notify payload with one of these types
/// that it does not recognize in a response MUST assume that the
/// corresponding request has failed entirely.  Unrecognized error types
/// in a request and status types in a request or response MUST be
/// ignored, and they should be logged.
///
/// Notify payloads with status types MAY be added to any message and
/// MUST be ignored if not recognized.  They are intended to indicate
/// capabilities, and as part of SA negotiation, are used to negotiate
/// non-cryptographic parameters.
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.10.1
///
/// Extensions:
///
/// - [RFC4555](https://tools.ietf.org/html/rfc4555) IKEv2 Mobility and Multihoming Protocol (MOBIKE)
/// - [RFC4739](https://tools.ietf.org/html/rfc4739) Multiple Authentication Exchanges in the Internet Key Exchange (IKEv2) Protocol
/// - [RFC5685](https://tools.ietf.org/html/rfc5685) Redirect Mechanism for the Internet Key Exchange Protocol Version 2 (IKEv2)
/// - [RFC5723](https://tools.ietf.org/html/rfc5723) Internet Key Exchange Protocol Version 2 (IKEv2) Session Resumption
/// - [RFC7427](https://tools.ietf.org/html/rfc7427) Signature Authentication in the Internet Key Exchange Version 2 (IKEv2)
///
/// See also [IKEV2IANA](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml) for the latest values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NotifyType(pub u16);

impl NotifyType {
    // error types
    pub const UNSUPPORTED_CRITICAL_PAYLOAD  : NotifyType = NotifyType(1);
    pub const INVALID_IKE_SPI               : NotifyType = NotifyType(4);
    pub const INVALID_MAJOR_VERSION         : NotifyType = NotifyType(5);
    pub const INVALID_SYNTAX                : NotifyType = NotifyType(7);
    pub const INVALID_MESSAGE_ID            : NotifyType = NotifyType(9);
    pub const INVALID_SPI                   : NotifyType = NotifyType(11);
    pub const NO_PROPOSAL_CHOSEN            : NotifyType = NotifyType(14);
    pub const INVALID_KE_PAYLOAD            : NotifyType = NotifyType(17);
    pub const AUTHENTICATION_FAILED         : NotifyType = NotifyType(24);
    pub const SINGLE_PAIR_REQUIRED          : NotifyType = NotifyType(34);
    pub const NO_ADDITIONAL_SAS             : NotifyType = NotifyType(35);
    pub const INTERNAL_ADDRESS_FAILURE      : NotifyType = NotifyType(36);
    pub const FAILED_CP_REQUIRED            : NotifyType = NotifyType(37);
    pub const TS_UNACCEPTABLE               : NotifyType = NotifyType(38);
    pub const INVALID_SELECTORS             : NotifyType = NotifyType(39);
    pub const TEMPORARY_FAILURE             : NotifyType = NotifyType(43);
    pub const CHILD_SA_NOT_FOUND            : NotifyType = NotifyType(44);
    // status types
    pub const INITIAL_CONTACT               : NotifyType = NotifyType(16384);
    pub const SET_WINDOW_SIZE               : NotifyType = NotifyType(16385);
    pub const ADDITIONAL_TS_POSSIBLE        : NotifyType = NotifyType(16386);
    pub const IPCOMP_SUPPORTED              : NotifyType = NotifyType(16387);
    pub const NAT_DETECTION_SOURCE_IP       : NotifyType = NotifyType(16388);
    pub const NAT_DETECTION_DESTINATION_IP  : NotifyType = NotifyType(16389);
    pub const COOKIE                        : NotifyType = NotifyType(16390);
    pub const USE_TRANSPORT_MODE            : NotifyType = NotifyType(16391);
    pub const HTTP_CERT_LOOKUP_SUPPORTED    : NotifyType = NotifyType(16392);
    pub const REKEY_SA                      : NotifyType = NotifyType(16393);
    pub const ESP_TFC_PADDING_NOT_SUPPORTED : NotifyType = NotifyType(16394);
    pub const NON_FIRST_FRAGMENTS_ALSO      : NotifyType = NotifyType(16395);
    //
    pub const MULTIPLE_AUTH_SUPPORTED       : NotifyType = NotifyType(16404);
    pub const ANOTHER_AUTH_FOLLOWS          : NotifyType = NotifyType(16405);
    pub const REDIRECT_SUPPORTED            : NotifyType = NotifyType(16406);
    //
    pub const IKEV2_FRAGMENTATION_SUPPORTED : NotifyType = NotifyType(16430);
    pub const SIGNATURE_HASH_ALGORITHMS     : NotifyType = NotifyType(16431);

    pub fn is_error(&self) -> bool { self.0 < 16384 }
    pub fn is_status(&self) -> bool { self.0 > 16384 }
}

impl fmt::Debug for NotifyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            1     => f.write_str("UNSUPPORTED_CRITICAL_PAYLOAD"),
            4     => f.write_str("INVALID_IKE_SPI"),
            5     => f.write_str("INVALID_MAJOR_VERSION"),
            7     => f.write_str("INVALID_SYNTAX"),
            9     => f.write_str("INVALID_MESSAGE_ID"),
            11    => f.write_str("INVALID_SPI"),
            14    => f.write_str("NO_PROPOSAL_CHOSEN"),
            17    => f.write_str("INVALID_KE_PAYLOAD"),
            24    => f.write_str("AUTHENTICATION_FAILED"),
            34    => f.write_str("SINGLE_PAIR_REQUIRED"),
            35    => f.write_str("NO_ADDITIONAL_SAS"),
            36    => f.write_str("INTERNAL_ADDRESS_FAILURE"),
            37    => f.write_str("FAILED_CP_REQUIRED"),
            38    => f.write_str("TS_UNACCEPTABLE"),
            39    => f.write_str("INVALID_SELECTORS"),
            43    => f.write_str("TEMPORARY_FAILURE"),
            44    => f.write_str("CHILD_SA_NOT_FOUND"),
            //
            16384 => f.write_str("INITIAL_CONTACT"),
            16385 => f.write_str("SET_WINDOW_SIZE"),
            16386 => f.write_str("ADDITIONAL_TS_POSSIBLE"),
            16387 => f.write_str("IPCOMP_SUPPORTED"),
            16388 => f.write_str("NAT_DETECTION_SOURCE_IP"),
            16389 => f.write_str("NAT_DETECTION_DESTINATION_IP"),
            16390 => f.write_str("COOKIE"),
            16391 => f.write_str("USE_TRANSPORT_MODE"),
            16392 => f.write_str("HTTP_CERT_LOOKUP_SUPPORTED"),
            16393 => f.write_str("REKEY_SA"),
            16394 => f.write_str("ESP_TFC_PADDING_NOT_SUPPORTED"),
            16395 => f.write_str("NON_FIRST_FRAGMENTS_ALSO"),
            //
            16404 => f.write_str("MULTIPLE_AUTH_SUPPORTED"),
            16405 => f.write_str("ANOTHER_AUTH_FOLLOWS"),
            16406 => f.write_str("REDIRECT_SUPPORTED"),
            //
            16430 => f.write_str("IKEV2_FRAGMENTATION_SUPPORTED"),
            16431 => f.write_str("SIGNATURE_HASH_ALGORITHMS"),
            //
            n     => f.debug_tuple("Notify").field(&n).finish(),
        }
    }
}
