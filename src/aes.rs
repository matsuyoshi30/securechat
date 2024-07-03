use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt};
use aes::Aes128;

pub const AES_BLOCK_SIZE: usize = 16;
const IV: [u8; 16] = *b"YELLOW SUBMARINE";

pub fn encrypt(m: &mut [u8], cipher: &Aes128) -> Vec<[u8; AES_BLOCK_SIZE]> {
    let bytes_padding = if m.len() % AES_BLOCK_SIZE != 0 {
        AES_BLOCK_SIZE - (m.len() % AES_BLOCK_SIZE)
    } else {
        0
    };

    // Pad the message using PKCS#7 Padding
    let mut m_padded = m.to_owned();
    m_padded.append(&mut [bytes_padding.try_into().unwrap()].repeat(bytes_padding));

    let mut plaintext_blocks = m_padded.chunks_exact(AES_BLOCK_SIZE);
    let first_block_slice = plaintext_blocks.next().unwrap();

    // XOR with the IV
    let first_block_vec: Vec<u8> = first_block_slice
        .iter()
        .zip(IV.iter())
        .map(|(x, y)| x ^ y)
        .collect();
    let first_block: [u8; AES_BLOCK_SIZE] = first_block_vec.try_into().unwrap();
    let mut first_block_arr = GenericArray::from(first_block);
    cipher.encrypt_block(&mut first_block_arr);

    let mut ciphertext_blocks: Vec<[u8; AES_BLOCK_SIZE]> = vec![];
    ciphertext_blocks.push(first_block_arr.into());

    // Iterate over every plaintext block. We've already done the first one manually
    for block in plaintext_blocks {
        // XOR with the last ciphertext block
        let last_c_block = ciphertext_blocks.last().unwrap();
        let block_xored_vec: Vec<u8> = block
            .iter()
            .zip(last_c_block.iter())
            .map(|(x, y)| x ^ y)
            .collect();
        let xored_block: [u8; AES_BLOCK_SIZE] = block_xored_vec.try_into().unwrap();
        let mut xored_block_arr = GenericArray::from(xored_block);
        cipher.encrypt_block(&mut xored_block_arr);
        ciphertext_blocks.push(xored_block_arr.into());
    }

    ciphertext_blocks
}

pub fn decrypt(m: &mut [u8], cipher: &Aes128) -> Vec<[u8; AES_BLOCK_SIZE]> {
    // These are the blocks we XOR each decrypted cipher block with
    let mut xor_with = vec![IV];

    // Split the ciphertext into blocks
    let ciphertext_blocks: Vec<[u8; AES_BLOCK_SIZE]> = m
        .chunks_exact(AES_BLOCK_SIZE)
        .map(|chunk| chunk.try_into().unwrap())
        .collect();
    xor_with.append(&mut ciphertext_blocks.clone());
    // The first ciphertext block is XORed with the IV, the second is XORed with the
    // First ciphertext block, etc. so we need to reverse the xor_with vector
    xor_with.reverse();

    let mut plaintext_blocks = vec![];
    for block in ciphertext_blocks {
        let to_xor = xor_with.pop().unwrap();
        let mut block_arr = GenericArray::from(block);
        cipher.decrypt_block(&mut block_arr);
        let plain_block_vec: Vec<u8> = to_xor
            .iter()
            .zip(block_arr.iter())
            .map(|(x, y)| x ^ y)
            .collect();
        let plain_block: [u8; AES_BLOCK_SIZE] = plain_block_vec.try_into().unwrap();
        plaintext_blocks.push(plain_block);
    }

    // Number of bytes of padding
    let last_char = plaintext_blocks.last().unwrap()[AES_BLOCK_SIZE - 1];

    // If the message is padded
    if 0 < last_char && last_char < AES_BLOCK_SIZE as u8 {
        let mut last_block = plaintext_blocks.pop().unwrap();
        for i in AES_BLOCK_SIZE as u8 - last_char..AES_BLOCK_SIZE as u8 {
            last_block[i as usize] = 0;
        }
        plaintext_blocks.push(last_block);
    }

    plaintext_blocks
}
