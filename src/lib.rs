//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.

use aes::{
	cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
	Aes128,
};

use rand::Rng;

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	// Convert the inputs to the necessary data type
	let mut block = GenericArray::from(data);
	let key = GenericArray::from(*key);

	let cipher = Aes128::new(&key);

	cipher.encrypt_block(&mut block);

	block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	// Convert the inputs to the necessary data type
	let mut block = GenericArray::from(data);
	let key = GenericArray::from(*key);

	let cipher = Aes128::new(&key);

	cipher.decrypt_block(&mut block);

	block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
	// When twe have a multiple the second term is 0
	let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

	for _ in 0..number_pad_bytes {
		data.push(number_pad_bytes as u8);
	}

	data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
	let mut blocks = Vec::new();
	let mut i = 0;
	while i < data.len() {
		let mut block: [u8; BLOCK_SIZE] = Default::default();
		block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
		blocks.push(block);

		i += BLOCK_SIZE;
	}

	blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
	let mut data = Vec::new();
    for block in blocks {
        data.extend_from_slice(&block);
    }
    data
}

/// Does the opposite of the pad function.
fn un_pad(data: Vec<u8>) -> Vec<u8> {
	// The last byte indicates the number of pad bytes.
    let pad_byte = *data.last().expect("Data should not be empty");

    let pad_len = pad_byte as usize;
    let data_len = data.len();

    // Checks if the padding length is valid.
    if pad_len > BLOCK_SIZE || pad_len > data_len {
        return data;
    }
    // Checks if the added pad bytes are valid.
    // Iterates over the last bytes.
    for &byte in &data[data_len - pad_len..] {
        if byte != pad_byte {
            break;
        }
    }

    // Removing padding and return the original data.
    data[..data_len - pad_len].to_vec()
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
	// Pad the plaintext.
    let padded_plain_text = pad(plain_text);

    // Group the padded plaintext into blocks.
    let blocks = group(padded_plain_text);

    // Encrypt each block.
    let mut encrypted_blocks = Vec::new();
    for block in blocks {
        let encrypted_block = aes_encrypt(block, &key);
        encrypted_blocks.push(encrypted_block);
    }

    // Put the encrypted blocks into a vector.
    un_group(encrypted_blocks)
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	// Group the ciphertext into blocks.
    let blocks = group(cipher_text);

    // Decrypt each block.
    let mut decrypted_blocks = Vec::new();
    for block in blocks {
        let decrypted_block = aes_decrypt(block, &key);
        decrypted_blocks.push(decrypted_block);
    }

    // Put the decrypted blocks into plaintext vector.
    let decrypted_data = un_group(decrypted_blocks);

    // un_pad the decrypted data.
    un_pad(decrypted_data)
}

// XOR the blocks.
fn xor_blocks(block1: &[u8; BLOCK_SIZE], block2: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        result[i] = block1[i] ^ block2[i];
    }
    result
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	// Pad the plain text.
    let padded_plain_text = pad(plain_text);

    // Generate the random iv.
    let iv = rand::thread_rng().gen::<[u8; BLOCK_SIZE]>();

    // Group the padded plaintext into blocks.
    let blocks = group(padded_plain_text);

    let mut encrypted_blocks = Vec::new();
    let mut previous_block = iv;

    // Encrypt each block and push it to the vec.
    for block in blocks {
        let xored_block = xor_blocks(&block, &previous_block);
        let encrypted_block = aes_encrypt(xored_block, &key);
        encrypted_blocks.push(encrypted_block);
        previous_block = encrypted_block;
    }

    // Add the iv to the vector of encrypted blocks.
    let mut result = iv.to_vec();
    result.extend(un_group(encrypted_blocks));

    result
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	// Extract the IV from the ciphertext.
    let iv: [u8; BLOCK_SIZE] = cipher_text[..BLOCK_SIZE].try_into().expect("Invalid IV length");

    // Group the rest of the ciphertext into blocks.
    let blocks = group(cipher_text[BLOCK_SIZE..].to_vec());

    let mut decrypted_blocks = Vec::new();
    let mut previous_block = iv;

    // Decrypt each blockk.
    for block in blocks {
        let decrypted_block = aes_decrypt(block, &key);
        let xored_block = xor_blocks(&decrypted_block, &previous_block);
        decrypted_blocks.push(xored_block);
        previous_block = block;
    }

    // un_group blocks into a single plaintext vector.
    let decrypted_data = un_group(decrypted_blocks);

    // un_pad the decrypted data.
    un_pad(decrypted_data)
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	// Generate a random nonce.
    let mut rng = rand::thread_rng();
    let nonce: [u8; 8] = rng.gen();
    // Add the nonce to the result.
    let mut result = nonce.to_vec();

    // Split plaintext into blocks and process each block.
    for (counter, block) in plain_text.chunks(BLOCK_SIZE).enumerate() {
        // Construct the value V = nonce | counter.
        let mut counter_block = [0u8; BLOCK_SIZE];
        counter_block[..8].copy_from_slice(&nonce);
        counter_block[8..].copy_from_slice(&(counter as u64).to_be_bytes());

        // Encrypt the counter block using AES.
        let encrypted_counter_block = aes_encrypt(counter_block, &key);

        // XOR the counter block with the plaintext block.
        let block_array = {
            let mut arr = [0u8; BLOCK_SIZE];
            let len = block.len();
            arr[..len].copy_from_slice(&block);
            arr
        };
        let xor_result = xor_blocks(&encrypted_counter_block, &block_array);
        result.extend_from_slice(&xor_result);
    }

    result
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	// Extract the nonce from the ciphertext.
    let nonce: [u8; 8] = cipher_text[..8].try_into().expect("Invalid nonce length");

    let mut result = Vec::new();

    // Split ciphertext into blocks and process each block.
    for (counter, block) in cipher_text[8..].chunks(BLOCK_SIZE).enumerate() {
        // Construct the value V = nonce | counter
        let mut counter_block = [0u8; BLOCK_SIZE];
        counter_block[..8].copy_from_slice(&nonce);
        counter_block[8..].copy_from_slice(&(counter as u64).to_be_bytes());

        // Encrypt the counter block using AES.
        let encrypted_counter_block = aes_encrypt(counter_block, &key);

        // XOR the encrypted counter block with the ciphertext block
        let mut xor_result = vec![0u8; block.len()];
        for (i, &byte) in block.iter().enumerate() {
            // Decrypts.
            xor_result[i] = encrypted_counter_block[i] ^ byte;
        }
        
        // Append the relevant portion of the XOR result to vector.
        result.extend_from_slice(&xor_result);
    }

    // Remove zeroes from the result.
    while result.ends_with(&[0u8]) {
        result.pop();
    }

    result
}