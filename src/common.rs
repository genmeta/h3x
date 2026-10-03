pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod trailers;
pub mod wnd_buf;

pub struct Read;
pub struct Write;

/// Preserve repeated header values and QPACK sensitivity in both message kinds.
fn fields<'a>(
    pseudo: impl IntoIterator<Item = (&'static [u8], Option<&'a str>)>,
    headers: &http::HeaderMap,
) -> Vec<crate::qpack::Field> {
    use bytes::Bytes;

    use crate::qpack::Field;
    let mut fields: Vec<_> = pseudo
        .into_iter()
        .filter_map(|(name, value)| {
            value.map(|value| Field {
                name: Bytes::from_static(name),
                value: Bytes::copy_from_slice(value.as_bytes()),
                never_index: false,
            })
        })
        .collect();
    fields.extend(headers.iter().map(|(name, value)| Field {
        name: Bytes::copy_from_slice(name.as_str().as_bytes()),
        value: Bytes::copy_from_slice(value.as_bytes()),
        never_index: value.is_sensitive(),
    }));
    fields
}
