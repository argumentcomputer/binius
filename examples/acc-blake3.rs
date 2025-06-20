use std::{array, time::Instant};

use binius_circuits::{
	arithmetic::u32::LOG_U32_BITS,
	builder::{
		types::{F, U},
		ConstraintSystemBuilder,
	},
};
use binius_core::{
	constraint_system,
	constraint_system::validate::validate_witness,
	fiat_shamir::HasherChallenger,
	oracle::{OracleId, ShiftVariant},
	tower::CanonicalTowerFamily,
};
use binius_field::{BinaryField1b, BinaryField32b, Field, TowerField};
use binius_hal::make_portable_backend;
use binius_hash::groestl::{Groestl256, Groestl256ByteCompression};
use binius_macros::arith_expr;
use binius_utils::checked_arithmetics::log2_ceil_usize;
use bytesize::ByteSize;
use rand::{rngs::OsRng, Rng};

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

	// we have 7 rounds in total
	for round_idx in 0..7 {
		for j in 0..8 {
			let a_in = state[a[j]];
			let b_in = state[b[j]];
			let c_in = state[c[j]];
			let d_in = state[d[j]];
			let mx_in = state[mx[j]];
			let my_in = state[my[j]];

			let a_0 = a_in.wrapping_add(b_in).wrapping_add(mx_in);
			let d_0 = (d_in ^ a_0).rotate_right(16);
			let c_0 = c_in.wrapping_add(d_0);
			let b_0 = (b_in ^ c_0).rotate_right(12);

			let a_1 = a_0.wrapping_add(b_0).wrapping_add(my_in);
			let d_1 = (d_0 ^ a_1).rotate_right(8);
			let c_1 = c_0.wrapping_add(d_1);
			let b_1 = (b_0 ^ c_1).rotate_right(7);

			state[a[j]] = a_1;
			state[b[j]] = b_1;
			state[c[j]] = c_1;
			state[d[j]] = d_1;
		}

		// execute permutation for the 6 first rounds
		if round_idx < 6 {
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

// Circuit constants
const STATE_SIZE: usize = 32;

// This defines how long state columns should be
const SINGLE_STATE_TRANSITION_N_VARS: usize = 6;

// Number of initial state mutations until getting output value
const TEMP_STATE_OUT_INDEX: usize = 56;

// Number of initial state mutations (TEMP_STATE_OUT_INDEX) in "binary" form
const TEMP_STATE_OUT_INDEX_BINARY: [F; SINGLE_STATE_TRANSITION_N_VARS] = [
	Field::ZERO,
	Field::ZERO,
	Field::ZERO,
	Field::ONE,
	Field::ONE,
	Field::ONE,
];

const SINGLE_COMPRESSION_HEIGHT: usize = 2usize.pow(SINGLE_STATE_TRANSITION_N_VARS as u32);

const CV_HEIGHT: usize = 8;

const ADDITION_OPERATIONS_NUMBER: usize = 6;

type F32 = BinaryField32b;
type F1 = BinaryField1b;

struct TestVector {
	cv: [u32; 8],
	block: [u32; 16],
	counter_low: u32,
	counter_high: u32,
	block_len: u32,
	flags: u32,
	expected: [u32; 16],
}

pub struct Blake3CompressionOracles {
	pub input: [OracleId; STATE_SIZE],
	pub output: [OracleId; STATE_SIZE],
}

fn blake3_compression_circuit(
	builder: &mut ConstraintSystemBuilder,
	traces: &Vec<TestVector>,
) -> Blake3CompressionOracles {
	assert!(traces.len() >= 8);

	// state
	let state_n_vars = log2_ceil_usize(traces.len() * SINGLE_COMPRESSION_HEIGHT);
	let state_transitions: [OracleId; STATE_SIZE] = builder.add_committed_multiple(
		"state_transitions",
		state_n_vars,
		BinaryField32b::TOWER_LEVEL,
	);

	// input
	let input: [OracleId; STATE_SIZE] = array::from_fn(|xy| {
		builder
			.add_projected(
				"input",
				state_transitions[xy],
				vec![F::ZERO; SINGLE_STATE_TRANSITION_N_VARS],
				0,
			)
			.unwrap()
	});

	// output
	let output: [OracleId; STATE_SIZE] = array::from_fn(|xy| {
		builder
			.add_projected("output", state_transitions[xy], TEMP_STATE_OUT_INDEX_BINARY.to_vec(), 0)
			.unwrap()
	});

	// columns for enforcing cv computation
	let out_n_vars = log2_ceil_usize(traces.len() * CV_HEIGHT);
	let cv: OracleId = builder.add_committed("cv", out_n_vars, BinaryField32b::TOWER_LEVEL);
	let state_i = builder.add_committed("state_i", out_n_vars, BinaryField32b::TOWER_LEVEL);
	let state_i_8 = builder.add_committed("state_i_8", out_n_vars, BinaryField32b::TOWER_LEVEL);

	let state_i_xor_state_i_8 = builder
		.add_linear_combination(
			"state_i_xor_state_i_8",
			out_n_vars,
			[(state_i, F::ONE), (state_i_8, F::ONE)],
		)
		.unwrap();

	let cv_oracle_xor_state_i_8 = builder
		.add_linear_combination(
			"cv_oracle_xor_state_i_8",
			out_n_vars,
			[(cv, F::ONE), (state_i_8, F::ONE)],
		)
		.unwrap();

	// columns for enforcing correct computation of temp variables
	let a_in: OracleId =
		builder.add_committed("a_in", state_n_vars + 5, BinaryField1b::TOWER_LEVEL);
	let b_in: OracleId =
		builder.add_committed("b_in", state_n_vars + 5, BinaryField1b::TOWER_LEVEL);
	let c_in: OracleId =
		builder.add_committed("c_in", state_n_vars + 5, BinaryField1b::TOWER_LEVEL);
	let d_in: OracleId =
		builder.add_committed("d_in", state_n_vars + 5, BinaryField1b::TOWER_LEVEL);
	let mx_in: OracleId =
		builder.add_committed("mx_in", state_n_vars + 5, BinaryField1b::TOWER_LEVEL);
	let my_in: OracleId =
		builder.add_committed("my_in", state_n_vars + 5, BinaryField1b::TOWER_LEVEL);
	let a_0_tmp: OracleId =
		builder.add_committed("a_0_tmp", state_n_vars + 5, BinaryField1b::TOWER_LEVEL);
	let a_0: OracleId = builder.add_committed("a_0", state_n_vars + 5, BinaryField1b::TOWER_LEVEL);
	let c_0: OracleId = builder.add_committed("c_0", state_n_vars + 5, BinaryField1b::TOWER_LEVEL);
	let b_in_xor_c_0: OracleId = builder
		.add_linear_combination("b_in_xor_c_0", state_n_vars + 5, [(b_in, F::ONE), (c_0, F::ONE)])
		.unwrap();
	let b_0: OracleId = builder
		.add_shifted(
			"d_1",
			b_in_xor_c_0,
			(32 - 12) as usize,
			LOG_U32_BITS,
			ShiftVariant::CircularLeft,
		)
		.unwrap();
	let d_in_xor_a_0: OracleId = builder
		.add_linear_combination("d_in_xor_a_0", state_n_vars + 5, [(d_in, F::ONE), (a_0, F::ONE)])
		.unwrap();
	let d_0: OracleId = builder
		.add_shifted(
			"d_0",
			d_in_xor_a_0,
			(32 - 16) as usize,
			LOG_U32_BITS,
			ShiftVariant::CircularLeft,
		)
		.unwrap();
	let a_1_tmp: OracleId =
		builder.add_committed("a_1_tmp", state_n_vars + 5, BinaryField1b::TOWER_LEVEL);
	let a_1: OracleId = builder.add_committed("a_1", state_n_vars + 5, BinaryField1b::TOWER_LEVEL);
	let d_0_xor_a_1: OracleId = builder
		.add_linear_combination("d_0_xor_a_1", state_n_vars + 5, [(d_0, F::ONE), (a_1, F::ONE)])
		.unwrap();
	let d_1: OracleId = builder
		.add_shifted(
			"d_1",
			d_0_xor_a_1,
			(32 - 8) as usize,
			LOG_U32_BITS,
			ShiftVariant::CircularLeft,
		)
		.unwrap();
	let c_1: OracleId = builder.add_committed("c_1", state_n_vars + 5, BinaryField1b::TOWER_LEVEL);
	let b_0_xor_c_1: OracleId = builder
		.add_linear_combination("b_0_xor_c_1", state_n_vars + 5, [(b_0, F::ONE), (c_1, F::ONE)])
		.unwrap();
	let b_1: OracleId = builder
		.add_shifted(
			"b_1",
			b_0_xor_c_1,
			(32 - 7) as usize,
			LOG_U32_BITS,
			ShiftVariant::CircularLeft,
		)
		.unwrap();

	let cout: [OracleId; ADDITION_OPERATIONS_NUMBER] =
		builder.add_committed_multiple("cout", state_n_vars + 5, F1::TOWER_LEVEL);
	let cin: [OracleId; ADDITION_OPERATIONS_NUMBER] = array::from_fn(|xy| {
		builder
			.add_shifted("cin", cout[xy], 1, 5, ShiftVariant::LogicalLeft)
			.unwrap()
	});

	// witness population (columns creation and data writing)
	if let Some(witness) = builder.witness() {
		// columns creation

		let mut state_cols = state_transitions.map(|id| witness.new_column::<F32>(id));
		let mut input_cols = input.map(|id| witness.new_column::<F32>(id));
		let mut output_cols = output.map(|id| witness.new_column::<F32>(id));

		let mut cv_col = witness.new_column::<F32>(cv);
		let mut state_i_col = witness.new_column::<F32>(state_i);
		let mut state_i_8_col = witness.new_column::<F32>(state_i_8);
		let mut state_i_xor_state_i_8_col = witness.new_column::<F32>(state_i_xor_state_i_8);
		let mut cv_oracle_xor_state_i_8_col = witness.new_column::<F32>(cv_oracle_xor_state_i_8);

		let mut a_in_col = witness.new_column::<F1>(a_in);
		let mut b_in_col = witness.new_column::<F1>(b_in);
		let mut c_in_col = witness.new_column::<F1>(c_in);
		let mut d_in_col = witness.new_column::<F1>(d_in);
		let mut mx_in_col = witness.new_column::<F1>(mx_in);
		let mut my_in_col = witness.new_column::<F1>(my_in);
		let mut a_0_tmp_col = witness.new_column::<F1>(a_0_tmp);
		let mut a_0_col = witness.new_column::<F1>(a_0);
		let mut b_in_xor_c_0_col = witness.new_column::<F1>(b_in_xor_c_0);
		let mut b_0_col = witness.new_column::<F1>(b_0);
		let mut c_0_col = witness.new_column::<F1>(c_0);
		let mut d_in_xor_a_0_col = witness.new_column::<F1>(d_in_xor_a_0);
		let mut d_0_col = witness.new_column::<F1>(d_0);
		let mut a_1_tmp_col = witness.new_column::<F1>(a_1_tmp);
		let mut a_1_col = witness.new_column::<F1>(a_1);
		let mut d_0_xor_a_1_col = witness.new_column::<F1>(d_0_xor_a_1);
		let mut d_1_col = witness.new_column::<F1>(d_1);
		let mut c_1_col = witness.new_column::<F1>(c_1);
		let mut b_0_xor_c_1_col = witness.new_column::<F1>(b_0_xor_c_1);
		let mut b_1_col = witness.new_column::<F1>(b_1);
		let mut cout_cols = cout.map(|id| witness.new_column::<F1>(id));
		let mut cin_cols = cin.map(|id| witness.new_column::<F1>(id));

		// values

		let state_vals = state_cols.each_mut().map(|col| col.as_mut_slice::<u32>());
		let input_vals = input_cols.each_mut().map(|col| col.as_mut_slice::<u32>());
		let output_vals = output_cols.each_mut().map(|col| col.as_mut_slice::<u32>());

		let cv_vals = cv_col.as_mut_slice::<u32>();
		let state_i_vals = state_i_col.as_mut_slice::<u32>();
		let state_i_8_vals = state_i_8_col.as_mut_slice::<u32>();
		let state_i_xor_state_i_8_vals = state_i_xor_state_i_8_col.as_mut_slice::<u32>();
		let cv_oracle_xor_state_i_8_vals = cv_oracle_xor_state_i_8_col.as_mut_slice::<u32>();

		let a_in_vals = a_in_col.as_mut_slice::<u32>();
		let b_in_vals = b_in_col.as_mut_slice::<u32>();
		let c_in_vals = c_in_col.as_mut_slice::<u32>();
		let d_in_vals = d_in_col.as_mut_slice::<u32>();
		let mx_in_vals = mx_in_col.as_mut_slice::<u32>();
		let my_in_vals = my_in_col.as_mut_slice::<u32>();
		let a_0_tmp_vals = a_0_tmp_col.as_mut_slice::<u32>();
		let a_0_vals = a_0_col.as_mut_slice::<u32>();
		let b_in_xor_c_0_vals = b_in_xor_c_0_col.as_mut_slice::<u32>();
		let b_0_vals = b_0_col.as_mut_slice::<u32>();
		let c_0_vals = c_0_col.as_mut_slice::<u32>();
		let d_in_xor_a_0_vals = d_in_xor_a_0_col.as_mut_slice::<u32>();
		let d_0_vals = d_0_col.as_mut_slice::<u32>();
		let a_1_tmp_vals = a_1_tmp_col.as_mut_slice::<u32>();
		let a_1_vals = a_1_col.as_mut_slice::<u32>();
		let d_0_xor_a_1_vals = d_0_xor_a_1_col.as_mut_slice::<u32>();
		let d_1_vals = d_1_col.as_mut_slice::<u32>();
		let c_1_vals = c_1_col.as_mut_slice::<u32>();
		let b_0_xor_c_1_vals = b_0_xor_c_1_col.as_mut_slice::<u32>();
		let b_1_vals = b_1_col.as_mut_slice::<u32>();

		let cout_vals = cout_cols.each_mut().map(|col| col.as_mut_slice::<u32>());
		let cin_vals = cin_cols.each_mut().map(|col| col.as_mut_slice::<u32>());

		/* Populating */

		// indices from Blake3 reference:
		// https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs#L53
		let a = [0, 1, 2, 3, 0, 1, 2, 3];
		let b = [4, 5, 6, 7, 5, 6, 7, 4];
		let c = [8, 9, 10, 11, 10, 11, 8, 9];
		let d = [12, 13, 14, 15, 15, 12, 13, 14];

		// we consider message 'm' as part of the state
		let mx = [16, 18, 20, 22, 24, 26, 28, 30];
		let my = [17, 19, 21, 23, 25, 27, 29, 31];

		let mut compression_offset = 0usize;
		for (compression_idx, trace) in traces.into_iter().enumerate() {
			let mut state_idx = 0;

			// populate state
			for i in 0..trace.cv.len() {
				state_vals[state_idx][compression_offset] = trace.cv[i];
				state_idx += 1;
			}

			state_vals[state_idx + 0][compression_offset] = IV[0];
			state_vals[state_idx + 1][compression_offset] = IV[1];
			state_vals[state_idx + 2][compression_offset] = IV[2];
			state_vals[state_idx + 3][compression_offset] = IV[3];
			state_vals[state_idx + 4][compression_offset] = trace.counter_low;
			state_vals[state_idx + 5][compression_offset] = trace.counter_high;
			state_vals[state_idx + 6][compression_offset] = trace.block_len;
			state_vals[state_idx + 7][compression_offset] = trace.flags;

			state_idx += 8;

			for i in 0..trace.block.len() {
				state_vals[state_idx][compression_offset] = trace.block[i];
				state_idx += 1;
			}

			// populate input, which consists from initial values of each state_transition
			for xy in 0..STATE_SIZE {
				input_vals[xy][compression_idx] = state_vals[xy][compression_offset];
			}

			assert_eq!(state_idx, STATE_SIZE);

			// we start from 1, since initial state is at 0
			let mut state_offset = 1usize;
			let mut temp_vars_offset = 0usize;

			fn add(a: u32, b: u32) -> (u32, u32, u32) {
				let cin;
				let cout;
				let zout;
				let carry;

				(zout, carry) = a.overflowing_add(b);
				cin = a ^ b ^ zout;
				cout = ((carry as u32) << 31) | (cin >> 1);

				(cin, cout, zout)
			}

			// state transition
			for round_idx in 0..7 {
				for j in 0..8 {
					let state_transition_idx = state_offset + compression_offset;
					let var_offset = temp_vars_offset + compression_offset;

					// column-wise copy of the previous state to the next one
					for i in 0..STATE_SIZE {
						state_vals[i][state_transition_idx] =
							state_vals[i][state_transition_idx - 1];
					}

					// take input from previous state
					a_in_vals[var_offset] = state_vals[a[j]][state_transition_idx - 1];
					b_in_vals[var_offset] = state_vals[b[j]][state_transition_idx - 1];
					c_in_vals[var_offset] = state_vals[c[j]][state_transition_idx - 1];
					d_in_vals[var_offset] = state_vals[d[j]][state_transition_idx - 1];
					mx_in_vals[var_offset] = state_vals[mx[j]][state_transition_idx - 1];
					my_in_vals[var_offset] = state_vals[my[j]][state_transition_idx - 1];

					// compute values of temp vars

					(cin_vals[0][var_offset], cout_vals[0][var_offset], a_0_tmp_vals[var_offset]) =
						add(a_in_vals[var_offset], b_in_vals[var_offset]);

					(cin_vals[1][var_offset], cout_vals[1][var_offset], a_0_vals[var_offset]) =
						add(a_0_tmp_vals[var_offset], mx_in_vals[var_offset]);

					d_in_xor_a_0_vals[var_offset] = d_in_vals[var_offset] ^ a_0_vals[var_offset];

					d_0_vals[var_offset] = d_in_xor_a_0_vals[var_offset].rotate_right(16);

					(cin_vals[2][var_offset], cout_vals[2][var_offset], c_0_vals[var_offset]) =
						add(c_in_vals[var_offset], d_0_vals[var_offset]);

					b_in_xor_c_0_vals[var_offset] = b_in_vals[var_offset] ^ c_0_vals[var_offset];

					b_0_vals[var_offset] = b_in_xor_c_0_vals[var_offset].rotate_right(12);

					(cin_vals[3][var_offset], cout_vals[3][var_offset], a_1_tmp_vals[var_offset]) =
						add(a_0_vals[var_offset], b_0_vals[var_offset]);

					(cin_vals[4][var_offset], cout_vals[4][var_offset], a_1_vals[var_offset]) =
						add(a_1_tmp_vals[var_offset], my_in_vals[var_offset]);

					d_0_xor_a_1_vals[var_offset] = d_0_vals[var_offset] ^ a_1_vals[var_offset];

					d_1_vals[var_offset] = d_0_xor_a_1_vals[var_offset].rotate_right(8);

					(cin_vals[5][var_offset], cout_vals[5][var_offset], c_1_vals[var_offset]) =
						add(c_0_vals[var_offset], d_1_vals[var_offset]);

					b_0_xor_c_1_vals[var_offset] = b_0_vals[var_offset] ^ c_1_vals[var_offset];

					b_1_vals[var_offset] = b_0_xor_c_1_vals[var_offset].rotate_right(7);

					// mutate state
					state_vals[a[j]][state_transition_idx] = a_1_vals[var_offset];
					state_vals[b[j]][state_transition_idx] = b_1_vals[var_offset];
					state_vals[c[j]][state_transition_idx] = c_1_vals[var_offset];
					state_vals[d[j]][state_transition_idx] = d_1_vals[var_offset];

					state_offset += 1;
					temp_vars_offset += 1;
				}

				// permutation (just shuffling the indices - no constraining is required)
				if round_idx < 6 {
					let mut permuted = [0u32; 16];
					for i in 0..16 {
						permuted[i] = state_vals[16 + MSG_PERMUTATION[i]]
							[state_offset + compression_offset - 1];
					}

					for i in 0..16 {
						state_vals[16 + i][state_offset + compression_offset - 1] = permuted[i];
					}
				}
			}

			assert_eq!(state_offset, TEMP_STATE_OUT_INDEX + 1);

			for i in 0..8 {
				// populate 'cv', 'state[i]' and 'state[i + 8]' columns
				cv_vals[i * compression_idx + i] = state_vals[i][compression_offset];
				state_i_vals[i * compression_idx + i] =
					state_vals[i][state_offset + compression_offset - 1];
				state_i_8_vals[i * compression_idx + i] =
					state_vals[i + 8][state_offset + compression_offset - 1];

				// compute 'state[i]' values
				state_vals[i][state_offset + compression_offset - 1] ^=
					state_vals[i + 8][state_offset + compression_offset - 1];

				// populate 'state[i] ^ state[i + 8]' linear combination
				state_i_xor_state_i_8_vals[i * compression_idx + i] =
					state_vals[i][state_offset + compression_offset - 1];

				// compute 'state[i + 8]' values
				state_vals[i + 8][state_offset + compression_offset - 1] ^=
					state_vals[i][compression_offset];

				// populate 'cv ^ state[i + 8]' linear combination
				cv_oracle_xor_state_i_8_vals[i * compression_idx + i] =
					state_vals[i + 8][state_offset + compression_offset - 1];
			}

			// copy final state transition (of the given compression) to the output
			for i in 0..STATE_SIZE {
				output_vals[i][compression_idx] =
					state_vals[i][state_offset + compression_offset - 1];
			}

			compression_offset += SINGLE_COMPRESSION_HEIGHT;

			// debug check
			assert!(output_vals.len() >= trace.expected.len());
			for i in 0..trace.expected.len() {
				assert_eq!(trace.expected[i], output_vals[i][compression_idx]);
			}
		}
	}

	/* Constraints */

	// TODO: remove this technical constraint (figure out how to properly constrain the 'state_i_8')
	builder.assert_zero("state_i_8", [state_i_8], arith_expr!([x] = x - x).convert_field());

	let xins = [a_in, a_0_tmp, c_in, a_0, a_1_tmp, c_0];
	let yins = [b_in, mx_in, d_0, b_0, my_in, d_1];
	let zouts = [a_0_tmp, a_0, c_0, a_1_tmp, a_1, c_1];

	for (idx, (xin, (yin, zout))) in xins
		.into_iter()
		.zip(yins.into_iter().zip(zouts.into_iter()))
		.enumerate()
	{
		builder.assert_zero(
			format!("sum{}", idx),
			[xin, yin, cin[idx], zout],
			arith_expr!([xin, yin, cin, zout] = xin + yin + cin - zout).convert_field(),
		);

		builder.assert_zero(
			format!("carry{}", idx),
			[xin, yin, cin[idx], cout[idx]],
			arith_expr!([xin, yin, cin, cout] = (xin + cin) * (yin + cin) + cin - cout)
				.convert_field(),
		);
	}

	Blake3CompressionOracles { input, output }
}

fn main() {
	// Out of circuit one-line blake3 computation - just for reference
	let input = vec![1u8; 100000];
	let expected = vec![
		53, 141, 211, 112, 176, 44, 170, 162, 62, 96, 62, 167, 158, 193, 48, 11, 87, 65, 249, 206,
		195, 147, 187, 29, 215, 203, 74, 149, 182, 220, 28, 157,
	];

	let reference_expected = blake3::hash(&input);
	assert_eq!(reference_expected.as_bytes().to_vec(), expected);

	let output = blake3_new_update_finalize(input);
	assert_eq!(expected, output);

	/* Circuit testing */

	// generate traces / test-vectors
	let compressions = 10000;

	let mut rng = OsRng;
	let traces = (0..compressions)
		.into_iter()
		.map(|_| {
			let cv: [u32; 8] = array::from_fn(|_| rng.gen::<u32>());
			let block: [u32; 16] = array::from_fn(|_| rng.gen::<u32>());
			let counter = rng.gen::<u64>();
			let counter_low = counter as u32;
			let counter_high = (counter >> 32) as u32;
			let block_len = rng.gen::<u32>();
			let flags = rng.gen::<u32>();

			let expected = compress(&cv, &block, counter, block_len, flags);

			TestVector {
				cv,
				block,
				counter_low,
				counter_high,
				block_len,
				flags,
				expected,
			}
		})
		.collect::<Vec<TestVector>>();

	let allocator = bumpalo::Bump::new();
	let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);

	// invoke circuit
	let _ = blake3_compression_circuit(&mut builder, &traces);

	let witness = builder.take_witness().unwrap();
	let cs = builder.build().unwrap();
	validate_witness(&cs, &vec![], &witness).unwrap();

	let backend = make_portable_backend();

	let start = Instant::now();
	let proof = constraint_system::prove::<
		U,
		CanonicalTowerFamily,
		Groestl256,
		Groestl256ByteCompression,
		HasherChallenger<Groestl256>,
		_,
	>(&cs, 1usize, 100usize, &[], witness, &backend)
	.unwrap();
	println!("Proving time: {:?}s", start.elapsed().as_secs());
	println!("Proof size: {}", ByteSize::b(proof.get_proof_size() as u64));

	let start = Instant::now();
	constraint_system::verify::<
		U,
		CanonicalTowerFamily,
		Groestl256,
		Groestl256ByteCompression,
		HasherChallenger<Groestl256>,
	>(&cs.no_base_constraints(), 1usize, 100usize, &[], proof)
	.unwrap();
	println!("Verification time: {:?}s", start.elapsed().as_secs());
}
