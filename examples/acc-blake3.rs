const IV: [u32; 8] = [
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const CHUNK_LEN: usize = 1024;
const BLOCK_LEN: usize = 64;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const OUT_LEN: usize = 32;
const ROOT: u32 = 1 << 3;

fn compress(
	chaining_value: &[u32; 8],
	block_words: &[u32; 16],
	counter: u64,
	block_len: u32,
	flags: u32,
) -> [u32; 16] {
	let counter_low = counter as u32;
	let counter_high = (counter >> 32) as u32;

	#[rustfmt::skip]
    let mut state = [
        chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3],
        chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7],
        IV[0],             IV[1],             IV[2],             IV[3],
        counter_low,       counter_high,      block_len,         flags,
		block_words[0], block_words[1], block_words[2], block_words[3],
		block_words[4], block_words[5], block_words[6], block_words[7],
		block_words[8], block_words[9], block_words[10], block_words[11],
		block_words[12], block_words[13], block_words[14], block_words[15],
    ];

	let a = [0, 1, 2, 3, 0, 1, 2, 3];
	let b = [4, 5, 6, 7, 5, 6, 7, 4];
	let c = [8, 9, 10, 11, 10, 11, 8, 9];
	let d = [12, 13, 14, 15, 15, 12, 13, 14];
	let mx = [16, 18, 20, 22, 24, 26, 28, 30];
	let my = [17, 19, 21, 23, 25, 27, 29, 31];

	for round_idx in 0..7 {
		for j in 0..8 {
			state[a[j]] = state[a[j]].wrapping_add(state[b[j]]).wrapping_add(state[mx[j]]);
			state[d[j]] = (state[d[j]] ^ state[a[j]]).rotate_right(16);
			state[c[j]] = state[c[j]].wrapping_add(state[d[j]]);
			state[b[j]] = (state[b[j]] ^ state[c[j]]).rotate_right(12);
			state[a[j]] = state[a[j]].wrapping_add(state[b[j]]).wrapping_add(state[my[j]]);
			state[d[j]] = (state[d[j]] ^ state[a[j]]).rotate_right(8);
			state[c[j]] = state[c[j]].wrapping_add(state[d[j]]);
			state[b[j]] = (state[b[j]] ^ state[c[j]]).rotate_right(7);
		}

		// permutation
		if round_idx != 7 {
			let mut permuted = [0; 16];
			for i in 0..16 {
				permuted[i] = state[16 + MSG_PERMUTATION[i]];
			}
			for i in 0..16 {
				state[i + 16] = permuted[i];
			}
		}
	}

	for i in 0..8 {
		state[i] ^= state[i + 8];
		state[i + 8] ^= chaining_value[i];
	}

	let state_out: [u32; 16] = std::array::from_fn(|i| state[i]);
	state_out
}



fn words_from_little_endian_bytes(bytes: &[u8], words: &mut [u32]) {
	debug_assert_eq!(bytes.len(), 4 * words.len());
	for (four_bytes, word) in bytes.chunks_exact(4).zip(words) {
		*word = u32::from_le_bytes(four_bytes.try_into().unwrap());
	}
}

fn first_8_words(compression_output: [u32; 16]) -> [u32; 8] {
	compression_output[0..8].try_into().unwrap()
}

fn start_flag(blocks_compressed: u8) -> u32 {
	if blocks_compressed == 0 {
		CHUNK_START
	} else {
		0
	}
}

fn blake3_new_update_finalize(input_: Vec<u8>) -> [u8; 32] {
	let input = input_.clone();
	let mut input = input.as_slice();

	let mut output = [0u8; 32];

	/* New */

	// Hasher
	let hasher_key_words = IV;
	let mut hasher_cv_stack = [[0u32; 8]; 54];
	let mut hasher_cv_stack_len = 0u32;
	let hasher_flags = 0u32;

	// ChunkState
	let mut chunk_state_chaining_value = hasher_key_words;
	let mut chunk_state_chunk_counter = 0u64;
	let mut chunk_state_block = [0u8; BLOCK_LEN];
	let mut chunk_state_block_len = 0u8;
	let mut chunk_state_blocks_compressed = 0u8;
	let mut chunk_state_flags = hasher_flags;


	/* Update */
	while !input.is_empty() {
		let chunk_state_len =
			BLOCK_LEN * chunk_state_blocks_compressed as usize + chunk_state_block_len as usize;
		//println!("chunk_state_len: {:?}", chunk_state_len);
		if CHUNK_LEN == chunk_state_len {
			// output
			let mut block_words = [0; 16];
			words_from_little_endian_bytes(&chunk_state_block, &mut block_words);
			let chaining_value = chunk_state_chaining_value;
			let counter = chunk_state_chunk_counter;
			let block_len = chunk_state_block_len;
			let flags = chunk_state_flags | start_flag(chunk_state_blocks_compressed) | CHUNK_END;

			// chaining_value
			let chaining_value = first_8_words(compress(
				&chaining_value,
				&block_words,
				counter,
				block_len as u32,
				flags,
			));

			let chunk_cv = chaining_value;
			let total_chunks = chunk_state_chunk_counter + 1;

			// add_chunk_chaining_value
			let mut new_cv = chunk_cv;
			let mut total_chunks_inner = total_chunks;
			while total_chunks_inner & 1 == 0 {
				// pop_stack
				hasher_cv_stack_len -= 1;
				let pop_stack = hasher_cv_stack[hasher_cv_stack_len as usize];
				let key_words = hasher_key_words;

				// parent_cv
				let left_child_cv = pop_stack;
				let right_child_cv = new_cv;

				// parent_output
				let mut block_words = [0u32; 16];
				block_words[..8].copy_from_slice(&left_child_cv);
				block_words[8..].copy_from_slice(&right_child_cv);

				let input_chaining_value = key_words;
				let counter = 0u64;
				let block_len = BLOCK_LEN as u32;
				let flags = PARENT | hasher_flags;

				// chaining_value
				new_cv = first_8_words(compress(
					&input_chaining_value,
					&block_words,
					counter,
					block_len as u32,
					flags,
				));

				total_chunks_inner >>= 1;
			}

			// push_stack
			let cv = new_cv;
			hasher_cv_stack[hasher_cv_stack_len as usize] = cv;
			hasher_cv_stack_len += 1;

			// ChunkState::new(self.key_words, total_chunks, self.flags);
			chunk_state_chaining_value = hasher_key_words;
			chunk_state_chunk_counter = total_chunks;
			chunk_state_block = [0u8; BLOCK_LEN];
			chunk_state_block_len = 0u8;
			chunk_state_blocks_compressed = 0u8;
			chunk_state_flags = hasher_flags;
		}

		let chunk_state_len =
			BLOCK_LEN * chunk_state_blocks_compressed as usize + chunk_state_block_len as usize;
		let want = CHUNK_LEN - chunk_state_len;
		let take = std::cmp::min(want, input.len());

		// chunk_state.update(&input[..take])
		let mut input_inner = &input[..take];

		while !input_inner.is_empty() {
			if chunk_state_block_len as usize == BLOCK_LEN {
				let mut block_words = [0; 16];
				words_from_little_endian_bytes(&chunk_state_block, &mut block_words);

				chunk_state_chaining_value = first_8_words(compress(
					&chunk_state_chaining_value,
					&block_words,
					chunk_state_chunk_counter,
					BLOCK_LEN as u32,
					chunk_state_flags | start_flag(chunk_state_blocks_compressed),
				));

				chunk_state_blocks_compressed += 1;
				chunk_state_block = [0u8; BLOCK_LEN];
				chunk_state_block_len = 0;
			}

			let want = BLOCK_LEN - chunk_state_block_len as usize;
			let take = std::cmp::min(want, input_inner.len());
			chunk_state_block[chunk_state_block_len as usize..][..take]
				.copy_from_slice(&input_inner[..take]);
			chunk_state_block_len += take as u8;
			input_inner = &input_inner[take..];
		}

		input = &input[take..];
	}

	/* Finalize */

	// output
	let mut block_words = [0; 16];
	words_from_little_endian_bytes(&chunk_state_block, &mut block_words);
	let mut input_chaining_value = chunk_state_chaining_value;
	let mut counter = chunk_state_chunk_counter;
	let mut block_len = chunk_state_block_len as u32;
	let mut flags = chunk_state_flags | start_flag(chunk_state_blocks_compressed) | CHUNK_END;

	let mut parent_nodes_remaining = hasher_cv_stack_len as usize;
	while parent_nodes_remaining > 0 {
		parent_nodes_remaining -= 1;

		// output

		let left_child_cv = hasher_cv_stack[parent_nodes_remaining];

		// chaining_value
		let right_child_cv =
			first_8_words(compress(&input_chaining_value, &block_words, counter, block_len, flags));

		let mut block_words_inner = [0; 16];
		block_words_inner[..8].copy_from_slice(&left_child_cv);
		block_words_inner[8..].copy_from_slice(&right_child_cv);

		input_chaining_value = hasher_key_words;
		block_words = block_words_inner;
		counter = 0;
		block_len = BLOCK_LEN as u32;
		flags = PARENT | hasher_flags;
	}

	// root_output_bytes

	let mut output_block_counter = 0u64;
	for out_block in output.chunks_mut(2 * OUT_LEN) {

		let words = compress(
			&input_chaining_value,
			&block_words,
			output_block_counter,
			block_len,
			flags | ROOT,
		);

		for (word, out_word) in words.iter().zip(out_block.chunks_mut(4)) {
			out_word.copy_from_slice(&word.to_le_bytes()[..out_word.len()]);
		}
		output_block_counter += 1;
	}

	output
}


fn main() {
	let input = vec![1u8; 100000];
	let expected = vec![53, 141, 211, 112, 176, 44, 170, 162, 62, 96, 62, 167, 158, 193, 48, 11, 87, 65, 249, 206, 195, 147, 187, 29, 215, 203, 74, 149, 182, 220, 28, 157];

	let output = blake3_new_update_finalize(input);
	assert_eq!(expected, output);
}

