use serde_json;

pub fn decode_bencoded_value(encoded_value: &str) -> (serde_json::Value, &str) {
    match encoded_value.chars().next() {
        Some('0'..='9') => {
            // Example: "5:hello" -> "hello"
            if let Some((length, rest)) = encoded_value.split_once(':') {
                if let Ok(length) = length.parse::<usize>() {
                    return (rest[..length].to_string().into(), &rest[length..]);
                }
                return (serde_json::Value::Null, "");
            }
        }
        Some('i') => {
            // Example: "i52e" -> "52"
            if let Some((n, rest)) =
                encoded_value
                    .split_at(1)
                    .1
                    .split_once('e')
                    .and_then(|(digit, rest)| {
                        let n = digit.parse::<i64>().ok();
                        Some((n, rest))
                    })
            {
                return (n.into(), rest);
            }
            return (serde_json::Value::Null, "");
        }
        Some('l') => {
            //Example: "l5:helloi52ee" -> [“hello”,52]
            let mut values = Vec::new();
            let mut rest = encoded_value.split_at(1).1;
            while !rest.is_empty() && !rest.starts_with('e') {
                let (v, remainder)= decode_bencoded_value(rest);
                values.push(v);
                rest = remainder;
            }
            return (values.into(), &rest[1..]);
        }
        Some('d') => {
            //Example: "d3:foo3:bar5:helloi52ee" -> {"foo":"bar","hello":52}
            let mut dict = serde_json::Map::new();
            let mut rest = encoded_value.split_at(1).1;
            while !rest.is_empty() && !rest.starts_with('e') {
                let (k, remainder) = decode_bencoded_value(rest);
                let k = match k {
                    serde_json::Value::String(k) => k,
                    k => {
                        panic!("dict keys must be strings, not {k:?}");
                    }
                };
                let (v, remainder) = decode_bencoded_value(remainder);
                dict.insert(k, v);
                rest = remainder;
            }
            return (dict.into(), &rest[1..]);
        }
        _ => {}
    }
    panic!("Unhandled encoded value: {}", encoded_value)
}