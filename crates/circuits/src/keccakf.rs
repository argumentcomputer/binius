// Copyright 2024 Irreducible Inc.

use crate::{builder::ConstraintSystemBuilder, transparent::step_down};
use binius_core::{
	oracle::{OracleId, ShiftVariant},
	transparent::multilinear_extension::MultilinearExtensionTransparent,
};
use binius_field::{
	as_packed_field::{PackScalar, PackedType},
	underlier::{UnderlierType, WithUnderlier},
	BinaryField1b, ExtensionField, PackedField, TowerField,
};
use binius_macros::composition_poly;
use bytemuck::{pod_collect_to_vec, Pod};
use rand::{thread_rng, Rng};

pub fn keccakf<U, F, FBase>(
	builder: &mut ConstraintSystemBuilder<U, F, FBase>,
	log_size: usize,
) -> Result<[OracleId; 25], anyhow::Error>
where
	U: UnderlierType + Pod + PackScalar<F> + PackScalar<FBase> + PackScalar<BinaryField1b>,
	F: TowerField + ExtensionField<FBase>,
	FBase: TowerField,
{
	let round_consts_single = builder.add_transparent(
		"round_consts_single",
		MultilinearExtensionTransparent::<_, PackedType<U, F>, _>::from_values(into_packed_vec::<
			PackedType<U, BinaryField1b>,
		>(&KECCAKF_RC))?,
	)?;

	let round_consts = builder.add_repeating(
		"round_consts",
		round_consts_single,
		log_size - LOG_ROWS_PER_PERMUTATION,
	)?;
	let selector_single = step_down(
		builder,
		"selector_single",
		LOG_ROWS_PER_PERMUTATION,
		ROUNDS_PER_PERMUTATION << LOG_ROWS_PER_ROUND,
	)?;
	let selector =
		builder.add_repeating("selector", selector_single, log_size - LOG_ROWS_PER_PERMUTATION)?;
	let state_in: [OracleId; 25] =
		builder.add_committed_multiple("state_in", log_size, BinaryField1b::TOWER_LEVEL);
	let state_out: [OracleId; 25] =
		builder.add_committed_multiple("state_out", log_size, BinaryField1b::TOWER_LEVEL);
	let c: [OracleId; 5] =
		builder.add_committed_multiple("c", log_size, BinaryField1b::TOWER_LEVEL);
	let d: [OracleId; 5] =
		builder.add_committed_multiple("d", log_size, BinaryField1b::TOWER_LEVEL);
	let c_shift: [OracleId; 5] = std::array::from_fn(|x| {
		builder
			.add_shifted(format!("c[{x}]"), c[x], 1, 6, ShiftVariant::CircularLeft)
			.unwrap()
	});
	let a_theta: [OracleId; 25] = std::array::from_fn(|xy| {
		let x = xy % 5;
		builder
			.add_linear_combination(
				format!("a_theta[{xy}]"),
				log_size,
				[(state_in[xy], F::ONE), (d[x], F::ONE)],
			)
			.unwrap()
	});
	let b: [OracleId; 25] = std::array::from_fn(|xy| {
		if xy == 0 {
			a_theta[0]
		} else {
			builder
				.add_shifted(
					format!("b[{xy}]"),
					a_theta[PI[xy]],
					RHO[xy] as usize,
					6,
					ShiftVariant::CircularLeft,
				)
				.unwrap()
		}
	});
	let next_state_in: [OracleId; 25] = std::array::from_fn(|xy| {
		builder
			.add_shifted(
				format!("next_state_in[{xy}]"),
				state_in[xy],
				64,
				11,
				ShiftVariant::LogicalRight,
			)
			.unwrap()
	});

	if let Some(witness) = builder.witness() {
		let mut state_in = state_in.map(|id| witness.new_column::<BinaryField1b>(id, log_size));
		let mut state_out = state_out.map(|id| witness.new_column::<BinaryField1b>(id, log_size));
		let mut c = c.map(|id| witness.new_column::<BinaryField1b>(id, log_size));
		let mut d = d.map(|id| witness.new_column::<BinaryField1b>(id, log_size));
		let mut c_shift = c_shift.map(|id| witness.new_column::<BinaryField1b>(id, log_size));
		let mut a_theta = a_theta.map(|id| witness.new_column::<BinaryField1b>(id, log_size));
		let mut b = b.map(|id| witness.new_column::<BinaryField1b>(id, log_size));
		let mut next_state_in =
			next_state_in.map(|id| witness.new_column::<BinaryField1b>(id, log_size));
		let mut round_consts_single =
			witness.new_column::<BinaryField1b>(round_consts_single, LOG_ROWS_PER_PERMUTATION);
		let mut round_consts = witness.new_column::<BinaryField1b>(round_consts, log_size);
		let mut selector = witness.new_column::<BinaryField1b>(selector, log_size);

		let state_in_u64 = state_in.each_mut().map(|col| col.as_mut_slice::<u64>());
		let state_out_u64 = state_out.each_mut().map(|col| col.as_mut_slice::<u64>());
		let c_u64 = c.each_mut().map(|col| col.as_mut_slice::<u64>());
		let d_u64 = d.each_mut().map(|col| col.as_mut_slice::<u64>());
		let c_shift_u64 = c_shift.each_mut().map(|col| col.as_mut_slice::<u64>());
		let a_theta_u64 = a_theta.each_mut().map(|col| col.as_mut_slice::<u64>());
		let b_u64 = b.each_mut().map(|col| col.as_mut_slice::<u64>());
		let next_state_in_u64 = next_state_in
			.each_mut()
			.map(|col| col.as_mut_slice::<u64>());
		let round_consts_single_u64 = round_consts_single.as_mut_slice();
		let round_consts_u64 = round_consts.as_mut_slice();
		let selector_u64 = selector.as_mut_slice();

		let mut rng = thread_rng();

		round_consts_single_u64[0..(1 << LOG_ROUNDS_PER_PERMUTATION)]
			.copy_from_slice(&KECCAKF_RC[0..(1 << LOG_ROUNDS_PER_PERMUTATION)]);

		// Each round state is 64 rows
		// Each permutation is 24 round states
		for perm_i in 0..1 << (log_size - LOG_ROWS_PER_PERMUTATION) {
			let i = perm_i << LOG_ROUNDS_PER_PERMUTATION;

			// Randomly generate the initial permutation input
			let input: [u64; 25] = rng.gen();
			let output = {
				let mut output = input;
				tiny_keccak::keccakf(&mut output);
				output
			};

			// Assign the permutation input
			for xy in 0..25 {
				state_in_u64[xy][i] = input[xy];
			}

			// Expand trace columns for each round
			for (round_i, &keccakf_rc) in KECCAKF_RC
				.iter()
				.enumerate()
				.take(1 << LOG_ROUNDS_PER_PERMUTATION)
			{
				let i = i | round_i;

				for x in 0..5 {
					c_u64[x][i] = (0..5).fold(0, |acc, y| acc ^ state_in_u64[x + 5 * y][i]);
					c_shift_u64[x][i] = c_u64[x][i].rotate_left(1);
				}

				for x in 0..5 {
					d_u64[x][i] = c_u64[(x + 4) % 5][i] ^ c_shift_u64[(x + 1) % 5][i];
				}

				for x in 0..5 {
					for y in 0..5 {
						a_theta_u64[x + 5 * y][i] = state_in_u64[x + 5 * y][i] ^ d_u64[x][i];
					}
				}

				for xy in 0..25 {
					b_u64[xy][i] = a_theta_u64[PI[xy]][i].rotate_left(RHO[xy]);
				}

				for x in 0..5 {
					for y in 0..5 {
						let b0 = b_u64[x + 5 * y][i];
						let b1 = b_u64[(x + 1) % 5 + 5 * y][i];
						let b2 = b_u64[(x + 2) % 5 + 5 * y][i];
						state_out_u64[x + 5 * y][i] = b0 ^ (!b1 & b2);
					}
				}

				round_consts_u64[i] = keccakf_rc;
				state_out_u64[0][i] ^= round_consts_u64[i];
				if round_i < 31 {
					for xy in 0..25 {
						state_in_u64[xy][i + 1] = state_out_u64[xy][i];
						next_state_in_u64[xy][i] = state_out_u64[xy][i];
					}
				}

				selector_u64[i] = if round_i < 24 { u64::MAX } else { 0 };
			}

			// Assert correct output
			for xy in 0..25 {
				assert_eq!(state_out_u64[xy][i + 23], output[xy]);
			}
		}
	}

	let sum6 = composition_poly!([x0, x1, x2, x3, x4, x5] = x0 + x1 + x2 + x3 + x4 + x5);
	for x in 0..5 {
		builder.assert_zero(
			[
				c[x],
				state_in[x],
				state_in[x + 5],
				state_in[x + 5 * 2],
				state_in[x + 5 * 3],
				state_in[x + 5 * 4],
			],
			sum6,
		);
	}

	// C_{x-1} + shift_{6,1}(C_{x+1}) - D_x = 0
	let sum3 = composition_poly!([x0, x1, x2] = x0 + x1 + x2);
	for x in 0..5 {
		builder.assert_zero([c[(x + 4) % 5], c_shift[(x + 1) % 5], d[x]], sum3);
	}

	let chi_iota = composition_poly!([s, b0, b1, b2, rc] = s - (rc + b0 + (1 - b1) * b2));
	let chi = composition_poly!([s, b0, b1, b2] = s - (b0 + (1 - b1) * b2));
	for x in 0..5 {
		for y in 0..5 {
			if x == 0 && y == 0 {
				builder.assert_zero(
					[
						state_out[x + 5 * y],
						b[x + 5 * y],
						b[(x + 1) % 5 + 5 * y],
						b[(x + 2) % 5 + 5 * y],
						round_consts,
					],
					chi_iota,
				);
			} else {
				builder.assert_zero(
					[
						state_out[x + 5 * y],
						b[x + 5 * y],
						b[(x + 1) % 5 + 5 * y],
						b[(x + 2) % 5 + 5 * y],
					],
					chi,
				)
			}
		}
	}

	let consistency = composition_poly!(
		[state_out, next_state_in, select] = (state_out - next_state_in) * select
	);
	for xy in 0..25 {
		builder.assert_zero([state_out[xy], next_state_in[xy], selector], consistency)
	}

	Ok(state_out)
}

#[inline]
fn into_packed_vec<P>(src: &[impl Pod]) -> Vec<P>
where
	P: PackedField + WithUnderlier,
	P::Underlier: Pod,
{
	pod_collect_to_vec::<_, P::Underlier>(src)
		.into_iter()
		.map(P::from_underlier)
		.collect()
}

#[rustfmt::skip]
const RHO: [u32; 25] = [
	 0, 44, 43, 21, 14,
	28, 20,  3, 45, 61,
	 1,  6, 25,  8, 18,
	27, 36, 10, 15, 56,
	62, 55, 39, 41,  2,
];

#[rustfmt::skip]
const PI: [usize; 25] = [
	0, 6, 12, 18, 24,
	3, 9, 10, 16, 22,
	1, 7, 13, 19, 20,
	4, 5, 11, 17, 23,
	2, 8, 14, 15, 21,
];

const LOG_ROWS_PER_ROUND: usize = 6;
const LOG_ROUNDS_PER_PERMUTATION: usize = 5;
const LOG_ROWS_PER_PERMUTATION: usize = LOG_ROWS_PER_ROUND + LOG_ROUNDS_PER_PERMUTATION;
const ROUNDS_PER_PERMUTATION: usize = 24;

const KECCAKF_RC: [u64; 32] = [
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
	// Pad to 32 entries
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
];
