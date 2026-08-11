#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InvalidFormEncoding;

pub(crate) fn decode_text(value: &[u8], maximum: usize) -> Result<String, InvalidFormEncoding> {
    let mut decoded = Vec::with_capacity(value.len().min(maximum));
    decode_into(value, &mut decoded, maximum)?;
    String::from_utf8(decoded).map_err(|_| InvalidFormEncoding)
}

pub(crate) fn decode_into(
    value: &[u8],
    decoded: &mut Vec<u8>,
    maximum: usize,
) -> Result<(), InvalidFormEncoding> {
    let mut index = 0;
    while index < value.len() {
        if decoded.len() >= maximum {
            return Err(InvalidFormEncoding);
        }
        match value[index] {
            b'%' if index + 2 < value.len() => {
                let high = hex(value[index + 1]).ok_or(InvalidFormEncoding)?;
                let low = hex(value[index + 2]).ok_or(InvalidFormEncoding)?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'%' => return Err(InvalidFormEncoding),
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    Ok(())
}

const fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
