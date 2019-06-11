use std::fmt;

use rusticata_macros::debug::HexSlice;

use ikev2::*;
use ikev2_transforms::*;

// ------------------------- ikev2_transforms.rs ------------------------------
//
impl<'a> fmt::Debug for IkeV2RawTransform<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let (tf_type, tf_id) = match self.transform_type {
            IkeTransformType::EncryptionAlgorithm => {
                ("EncryptionAlgorithm".to_string(),format!("{:?}", self.transform_id))
            },
            IkeTransformType::PseudoRandomFunction => {
                ("PseudoRandomFunction".to_string(),format!("{:?}", self.transform_id))
            },
            IkeTransformType::IntegrityAlgorithm => {
                ("IntegrityAlgorithm".to_string(),format!("{:?}", self.transform_id))
            },
            IkeTransformType::DiffieHellmanGroup => {
                ("DiffieHellmanGroup".to_string(),format!("{:?}", self.transform_id))
            },
            IkeTransformType::ExtendedSequenceNumbers => {
                ("ExtendedSequenceNumbers".to_string(),format!("{:?}", self.transform_id))
            },
            _    => (format!("<Unknown transform type {}>", self.transform_type.0),"".to_string()),
        };
        fmt.debug_struct("IkeV2RawTransform")
            .field("last", &self.last)
            .field("reserved1", &self.reserved1)
            .field("transform_length", &self.transform_length)
            .field("transform_type", &tf_type)
            .field("reserved2", &self.reserved2)
            .field("transform_id", &tf_id)
            .field("attributes", &self.attributes)
            .finish()
    }
}

// ------------------------- ikev2.rs ------------------------------

impl<'a> fmt::Debug for NoncePayload<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("NoncePayload")
            .field("nonce_data", &HexSlice{d:self.nonce_data})
            .finish()
    }
}

impl<'a> fmt::Debug for NotifyPayload<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("NotifyPayload")
            .field("protocol_id", &self.protocol_id)
            .field("spi_size", &self.spi_size)
            .field("notify_type", &self.notify_type)
            .field("spi", &self.spi)
            .field("notify_data", &self.notify_data.map(|o|{HexSlice{d:o}}))
            .finish()
    }
}
