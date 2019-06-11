use std::fmt;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ErrorCode(pub i32);

impl ErrorCode {
    pub const KDC_ERR_NONE                          : ErrorCode = ErrorCode(0);
    pub const KDC_ERR_NAME_EXP                      : ErrorCode = ErrorCode(1);
    pub const KDC_ERR_SERVICE_EXP                   : ErrorCode = ErrorCode(2);
    pub const KDC_ERR_BAD_PVNO                      : ErrorCode = ErrorCode(3);
    pub const KDC_ERR_C_OLD_MAST_KVNO               : ErrorCode = ErrorCode(4);
    pub const KDC_ERR_S_OLD_MAST_KVNO               : ErrorCode = ErrorCode(5);
    pub const KDC_ERR_C_PRINCIPAL_UNKNOWN           : ErrorCode = ErrorCode(6);
    pub const KDC_ERR_S_PRINCIPAL_UNKNOWN           : ErrorCode = ErrorCode(7);
    pub const KDC_ERR_PRINCIPAL_NOT_UNIQUE          : ErrorCode = ErrorCode(8);
    pub const KDC_ERR_NULL_KEY                      : ErrorCode = ErrorCode(9);
    pub const KDC_ERR_CANNOT_POSTDATE               : ErrorCode = ErrorCode(10);
    pub const KDC_ERR_NEVER_VALID                   : ErrorCode = ErrorCode(11);
    pub const KDC_ERR_POLICY                        : ErrorCode = ErrorCode(12);
    pub const KDC_ERR_BADOPTION                     : ErrorCode = ErrorCode(13);
    pub const KDC_ERR_ETYPE_NOSUPP                  : ErrorCode = ErrorCode(14);
    pub const KDC_ERR_SUMTYPE_NOSUPP                : ErrorCode = ErrorCode(15);
    pub const KDC_ERR_PADATA_TYPE_NOSUPP            : ErrorCode = ErrorCode(16);
    pub const KDC_ERR_TRTYPE_NOSUPP                 : ErrorCode = ErrorCode(17);
    pub const KDC_ERR_CLIENT_REVOKED                : ErrorCode = ErrorCode(18);
    pub const KDC_ERR_SERVICE_REVOKED               : ErrorCode = ErrorCode(19);
    pub const KDC_ERR_TGT_REVOKED                   : ErrorCode = ErrorCode(20);
    pub const KDC_ERR_CLIENT_NOTYET                 : ErrorCode = ErrorCode(21);
    pub const KDC_ERR_SERVICE_NOTYET                : ErrorCode = ErrorCode(22);
    pub const KDC_ERR_KEY_EXPIRED                   : ErrorCode = ErrorCode(23);
    pub const KDC_ERR_PREAUTH_FAILED                : ErrorCode = ErrorCode(24);
    pub const KDC_ERR_PREAUTH_REQUIRED              : ErrorCode = ErrorCode(25);
    pub const KDC_ERR_SERVER_NOMATCH                : ErrorCode = ErrorCode(26);
    pub const KDC_ERR_MUST_USE_USER2USER            : ErrorCode = ErrorCode(27);
    pub const KDC_ERR_PATH_NOT_ACCEPTED             : ErrorCode = ErrorCode(28);
    pub const KDC_ERR_SVC_UNAVAILABLE               : ErrorCode = ErrorCode(29);
    pub const KRB_AP_ERR_BAD_INTEGRITY              : ErrorCode = ErrorCode(31);
    pub const KRB_AP_ERR_TKT_EXPIRED                : ErrorCode = ErrorCode(32);
    pub const KRB_AP_ERR_TKT_NYV                    : ErrorCode = ErrorCode(33);
    pub const KRB_AP_ERR_REPEAT                     : ErrorCode = ErrorCode(34);
    pub const KRB_AP_ERR_NOT_US                     : ErrorCode = ErrorCode(35);
    pub const KRB_AP_ERR_BADMATCH                   : ErrorCode = ErrorCode(36);
    pub const KRB_AP_ERR_SKEW                       : ErrorCode = ErrorCode(37);
    pub const KRB_AP_ERR_BADADDR                    : ErrorCode = ErrorCode(38);
    pub const KRB_AP_ERR_BADVERSION                 : ErrorCode = ErrorCode(39);
    pub const KRB_AP_ERR_MSG_TYPE                   : ErrorCode = ErrorCode(40);
    pub const KRB_AP_ERR_MODIFIED                   : ErrorCode = ErrorCode(41);
    pub const KRB_AP_ERR_BADORDER                   : ErrorCode = ErrorCode(42);
    pub const KRB_AP_ERR_BADKEYVER                  : ErrorCode = ErrorCode(44);
    pub const KRB_AP_ERR_NOKEY                      : ErrorCode = ErrorCode(45);
    pub const KRB_AP_ERR_MUT_FAIL                   : ErrorCode = ErrorCode(46);
    pub const KRB_AP_ERR_BADDIRECTION               : ErrorCode = ErrorCode(47);
    pub const KRB_AP_ERR_METHOD                     : ErrorCode = ErrorCode(48);
    pub const KRB_AP_ERR_BADSEQ                     : ErrorCode = ErrorCode(49);
    pub const KRB_AP_ERR_INAPP_CKSUM                : ErrorCode = ErrorCode(50);
    pub const KRB_AP_PATH_NOT_ACCEPTED              : ErrorCode = ErrorCode(51);
    pub const KRB_ERR_RESPONSE_TOO_BIG              : ErrorCode = ErrorCode(52);
    pub const KRB_ERR_GENERIC                       : ErrorCode = ErrorCode(60);
    pub const KRB_ERR_FIELD_TOOLONG                 : ErrorCode = ErrorCode(61);
    pub const KDC_ERROR_CLIENT_NOT_TRUSTED          : ErrorCode = ErrorCode(62);
    pub const KDC_ERROR_KDC_NOT_TRUSTED             : ErrorCode = ErrorCode(63);
    pub const KDC_ERROR_INVALID_SIG                 : ErrorCode = ErrorCode(64);
    pub const KDC_ERR_KEY_TOO_WEAK                  : ErrorCode = ErrorCode(65);
    pub const KDC_ERR_CERTIFICATE_MISMATCH          : ErrorCode = ErrorCode(66);
    pub const KRB_AP_ERR_NO_TGT                     : ErrorCode = ErrorCode(67);
    pub const KDC_ERR_WRONG_REALM                   : ErrorCode = ErrorCode(68);
    pub const KRB_AP_ERR_USER_TO_USER_REQUIRED      : ErrorCode = ErrorCode(69);
    pub const KDC_ERR_CANT_VERIFY_CERTIFICATE       : ErrorCode = ErrorCode(70);
    pub const KDC_ERR_INVALID_CERTIFICATE           : ErrorCode = ErrorCode(71);
    pub const KDC_ERR_REVOKED_CERTIFICATE           : ErrorCode = ErrorCode(72);
    pub const KDC_ERR_REVOCATION_STATUS_UNKNOWN     : ErrorCode = ErrorCode(73);
    pub const KDC_ERR_REVOCATION_STATUS_UNAVAILABLE : ErrorCode = ErrorCode(74);
    pub const KDC_ERR_CLIENT_NAME_MISMATCH          : ErrorCode = ErrorCode(75);
    pub const KDC_ERR_KDC_NAME_MISMATCH             : ErrorCode = ErrorCode(76);
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            0  => f.write_str("KDC_ERR_NONE"),
            1  => f.write_str("KDC_ERR_NAME_EXP"),
            2  => f.write_str("KDC_ERR_SERVICE_EXP"),
            3  => f.write_str("KDC_ERR_BAD_PVNO"),
            4  => f.write_str("KDC_ERR_C_OLD_MAST_KVNO"),
            5  => f.write_str("KDC_ERR_S_OLD_MAST_KVNO"),
            6  => f.write_str("KDC_ERR_C_PRINCIPAL_UNKNOWN"),
            7  => f.write_str("KDC_ERR_S_PRINCIPAL_UNKNOWN"),
            8  => f.write_str("KDC_ERR_PRINCIPAL_NOT_UNIQUE"),
            9  => f.write_str("KDC_ERR_NULL_KEY"),
            10 => f.write_str("KDC_ERR_CANNOT_POSTDATE"),
            11 => f.write_str("KDC_ERR_NEVER_VALID"),
            12 => f.write_str("KDC_ERR_POLICY"),
            13 => f.write_str("KDC_ERR_BADOPTION"),
            14 => f.write_str("KDC_ERR_ETYPE_NOSUPP"),
            15 => f.write_str("KDC_ERR_SUMTYPE_NOSUPP"),
            16 => f.write_str("KDC_ERR_PADATA_TYPE_NOSUPP"),
            17 => f.write_str("KDC_ERR_TRTYPE_NOSUPP"),
            18 => f.write_str("KDC_ERR_CLIENT_REVOKED"),
            19 => f.write_str("KDC_ERR_SERVICE_REVOKED"),
            20 => f.write_str("KDC_ERR_TGT_REVOKED"),
            21 => f.write_str("KDC_ERR_CLIENT_NOTYET"),
            22 => f.write_str("KDC_ERR_SERVICE_NOTYET"),
            23 => f.write_str("KDC_ERR_KEY_EXPIRED"),
            24 => f.write_str("KDC_ERR_PREAUTH_FAILED"),
            25 => f.write_str("KDC_ERR_PREAUTH_REQUIRED"),
            26 => f.write_str("KDC_ERR_SERVER_NOMATCH"),
            27 => f.write_str("KDC_ERR_MUST_USE_USER2USER"),
            28 => f.write_str("KDC_ERR_PATH_NOT_ACCEPTED"),
            29 => f.write_str("KDC_ERR_SVC_UNAVAILABLE"),
            31 => f.write_str("KRB_AP_ERR_BAD_INTEGRITY"),
            32 => f.write_str("KRB_AP_ERR_TKT_EXPIRED"),
            33 => f.write_str("KRB_AP_ERR_TKT_NYV"),
            34 => f.write_str("KRB_AP_ERR_REPEAT"),
            35 => f.write_str("KRB_AP_ERR_NOT_US"),
            36 => f.write_str("KRB_AP_ERR_BADMATCH"),
            37 => f.write_str("KRB_AP_ERR_SKEW"),
            38 => f.write_str("KRB_AP_ERR_BADADDR"),
            39 => f.write_str("KRB_AP_ERR_BADVERSION"),
            40 => f.write_str("KRB_AP_ERR_MSG_TYPE"),
            41 => f.write_str("KRB_AP_ERR_MODIFIED"),
            42 => f.write_str("KRB_AP_ERR_BADORDER"),
            44 => f.write_str("KRB_AP_ERR_BADKEYVER"),
            45 => f.write_str("KRB_AP_ERR_NOKEY"),
            46 => f.write_str("KRB_AP_ERR_MUT_FAIL"),
            47 => f.write_str("KRB_AP_ERR_BADDIRECTION"),
            48 => f.write_str("KRB_AP_ERR_METHOD"),
            49 => f.write_str("KRB_AP_ERR_BADSEQ"),
            50 => f.write_str("KRB_AP_ERR_INAPP_CKSUM"),
            51 => f.write_str("KRB_AP_PATH_NOT_ACCEPTED"),
            52 => f.write_str("KRB_ERR_RESPONSE_TOO_BIG"),
            60 => f.write_str("KRB_ERR_GENERIC"),
            61 => f.write_str("KRB_ERR_FIELD_TOOLONG"),
            62 => f.write_str("KDC_ERROR_CLIENT_NOT_TRUSTED"),
            63 => f.write_str("KDC_ERROR_KDC_NOT_TRUSTED"),
            64 => f.write_str("KDC_ERROR_INVALID_SIG"),
            65 => f.write_str("KDC_ERR_KEY_TOO_WEAK"),
            66 => f.write_str("KDC_ERR_CERTIFICATE_MISMATCH"),
            67 => f.write_str("KRB_AP_ERR_NO_TGT"),
            68 => f.write_str("KDC_ERR_WRONG_REALM"),
            69 => f.write_str("KRB_AP_ERR_USER_TO_USER_REQUIRED"),
            70 => f.write_str("KDC_ERR_CANT_VERIFY_CERTIFICATE"),
            71 => f.write_str("KDC_ERR_INVALID_CERTIFICATE"),
            72 => f.write_str("KDC_ERR_REVOKED_CERTIFICATE"),
            73 => f.write_str("KDC_ERR_REVOCATION_STATUS_UNKNOWN"),
            74 => f.write_str("KDC_ERR_REVOCATION_STATUS_UNAVAILABLE"),
            75 => f.write_str("KDC_ERR_CLIENT_NAME_MISMATCH"),
            76 => f.write_str("KDC_ERR_KDC_NAME_MISMATCH"),
            n  => f.debug_tuple("ErrorCode").field(&n).finish(),
        }
    }
}

