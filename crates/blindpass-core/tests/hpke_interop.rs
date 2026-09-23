// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_core::custody::RecipientKeyPair;

const RECIPIENT_PRIVATE_KEY: &str = "c1e8cObDnJ+zNIi2N4w2pij9W+7zyLjZ1uPzXl9rtiQ=";
const RECIPIENT_PUBLIC_KEY: &str = "SeSHTiX+OJ7Tyfov0J0HeQfsxYCchhniEnEotqcsfHo=";
const EPHEMERAL_PRIVATE_KEY: &str = "etgA7CAkVksCvdzoBzEFw7J19fR08vNgj/WmG8ILVGw=";
const ENCAPSULATED_KEY: &str = "EEXh6QK3jX90xmhxawIr1RM3jVUqUm1lM+8W4oZ0nD0=";
const CIPHERTEXT: &str = "MSOUZWLXTrV7x7IOHQzp0BE+xE4gU+ux2c1rMq9gdfhEbp5Azgfm3g==";
const AAD: &str = "UDAxLUFBRA==";
const PLAINTEXT: &[u8] = b"P01-CROSS-RUNTIME-CANARY";

#[test]
fn opens_hpke_js_vector_and_matches_js_seal_output() {
    let recipient_private = decode(RECIPIENT_PRIVATE_KEY);
    let recipient_public = decode(RECIPIENT_PUBLIC_KEY);
    let ephemeral_private = decode(EPHEMERAL_PRIVATE_KEY);
    let enc = decode(ENCAPSULATED_KEY);
    let ciphertext = decode(CIPHERTEXT);
    let aad = decode(AAD);
    let recipient = RecipientKeyPair::from_private_key(&recipient_private).unwrap();

    assert_eq!(recipient.public_key(), recipient_public.as_slice());
    let opened = recipient.open(&enc, &ciphertext, &aad).unwrap();
    assert_eq!(opened.as_bytes(), PLAINTEXT);

    let sealed = RecipientKeyPair::seal_with_ephemeral_private(
        &recipient_public,
        &ephemeral_private,
        PLAINTEXT,
        &aad,
    )
    .unwrap();
    assert_eq!(sealed.enc, enc);
    assert_eq!(sealed.ciphertext, ciphertext);
}

#[test]
fn opens_rfc_9180_appendix_a_2_1_1_base_mode_vector() {
    let recipient_private =
        decode_hex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
    let enc = decode_hex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    let info = decode_hex("4f6465206f6e2061204772656369616e2055726e");
    let aad = decode_hex("436f756e742d30");
    let ciphertext = decode_hex(
        "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
    );
    let recipient = RecipientKeyPair::from_private_key(&recipient_private).unwrap();

    let opened = recipient
        .open_with_info(&enc, &ciphertext, &info, &aad)
        .unwrap();
    assert_eq!(opened.as_bytes(), b"Beauty is truth, truth beauty");
    assert!(
        recipient
            .open_with_info(&enc, &ciphertext, b"wrong info", &aad)
            .is_err()
    );
    assert!(
        recipient
            .open_with_info(&[0; 32], &ciphertext, &info, &aad)
            .is_err()
    );
    assert!(
        recipient
            .open_with_info(&enc, &ciphertext[..16], &info, &aad)
            .is_err()
    );
}

fn decode(input: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in input.bytes() {
        if byte == b'=' {
            break;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid fixture base64"),
        } as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    output
}

fn decode_hex(input: &str) -> Vec<u8> {
    let (pairs, remainder) = input.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap();
            let low = (pair[1] as char).to_digit(16).unwrap();
            ((high << 4) | low) as u8
        })
        .collect()
}
