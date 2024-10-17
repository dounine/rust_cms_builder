use base64::{engine::general_purpose::STANDARD, Engine as _};

pub fn decode<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    STANDARD.decode(data).unwrap()
}
pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
    STANDARD.encode(data)
}
