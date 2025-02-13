// Copyright 2024-2025 Irreducible Inc.

use std::time::Instant;
use std::collections::HashMap;

use binius_core::{
	constraint_system::channel::ChannelId, oracle::OracleId, transparent::constant::Constant,
};
use binius_field::{
	as_packed_field::PackScalar, underlier::WithUnderlier, BinaryField, BinaryField64b, ExtensionField, Field, TowerField
};
use binius_maybe_rayon::prelude::*;
use bytemuck::Pod;

use crate::builder::{
	types::{F, U},
	ConstraintSystemBuilder,
};

type M = BinaryField64b;
const M_GEN: M = M::MULTIPLICATIVE_GENERATOR;

pub fn provide<FS>(
	builder: &mut ConstraintSystemBuilder,
	channel: ChannelId,
	multiplicity: OracleId,
	table: OracleId,
	table_count: usize,
) -> Result<(), anyhow::Error>
where
	U: PackScalar<FS> + Pod,
	F: ExtensionField<FS>,
	FS: TowerField + Pod,
{
	let log_n = table_count.ilog2() as usize;
	let ones = builder.add_transparent(format!("ones-{channel}"), Constant::new(log_n, M::ONE))?;
	if let Some(witness) = builder.witness() {
		witness.new_column_with_default::<M>(ones, M::ONE);
	}
	let send_args = [table, ones];
	let receive_args = [table, multiplicity];
	builder.send(channel, table_count, send_args)?;
	builder.receive(channel, table_count, receive_args)?;
	Ok(())
}

pub fn require<FS>(
	builder: &mut ConstraintSystemBuilder,
	channel: ChannelId,
	prev_index: OracleId,
	lookup_values: OracleId,
	lookup_values_count: usize,
) -> Result<(), anyhow::Error>
where
	U: PackScalar<FS> + Pod,
	F: ExtensionField<FS>,
	FS: TowerField + Pod,
{
	let log_n = lookup_values_count.ilog2() as usize;
	let index =
		builder.add_linear_combination(format!("index-{channel}"), log_n, [(prev_index, M_GEN.into())])?;
	if let Some(witness) = builder.witness() {
		(
			witness.get::<M>(prev_index)?.as_slice::<u64>(),
			witness.new_column::<F>(index).as_mut_slice::<u128>(),
		)
			.into_par_iter()
			.for_each(|(prev, index)| *index = (F::from_underlier(*prev as u128) * M_GEN).to_underlier());
	}
	let receive_args = [lookup_values, prev_index];
	let send_args = [lookup_values, index];
	builder.receive(channel, lookup_values_count, receive_args)?;
	builder.send(channel, lookup_values_count, send_args)?;
	Ok(())
}

fn populate_require_hints<FS>(
	builder: &mut ConstraintSystemBuilder,
	table: OracleId,
	table_count: usize,
	lookup_values: OracleId,
	lookup_values_count: usize,
) -> Result<(OracleId, OracleId), anyhow::Error>
where
	U: PackScalar<FS> + Pod,
	F: ExtensionField<FS>,
	FS: TowerField + Pod + Ord,
{
	let multiplicity =
		builder.add_committed("multiplicity", table_count.ilog2() as usize, M::TOWER_LEVEL);
	let prev_index =
		builder.add_committed("prev_index", lookup_values_count.ilog2() as usize, M::TOWER_LEVEL);
	if let Some(witness) = builder.witness() {
		let mut mult_map = HashMap::new();
		let lookup_values_slice =
			&witness.get::<FS>(lookup_values)?.as_slice::<FS>()[0..lookup_values_count];
		let mut prev_index_vec = Vec::with_capacity(lookup_values_count);
		for f in lookup_values_slice {
			let prev = mult_map.entry(f).or_insert(M::ONE);
			prev_index_vec.push(*prev);
			*prev *= M_GEN;
		}
		let table_slice = &witness.get::<FS>(table)?.as_slice::<FS>()[0..table_count];
		let mut mult_vec = Vec::with_capacity(table_count);
		for f in table_slice {
			let mult = mult_map.get(&f).copied().unwrap_or(M::ONE);
			mult_vec.push(mult);
		}
		witness.new_column::<M>(multiplicity).as_mut_slice::<M>()[0..table_count]
			.copy_from_slice(&mult_vec);
		witness.new_column::<M>(prev_index).as_mut_slice::<M>()[0..lookup_values_count]
			.copy_from_slice(&prev_index_vec);
	}
	Ok((multiplicity, prev_index))
}

pub fn provide_require_lookup<FS>(
	builder: &mut ConstraintSystemBuilder,
	table: OracleId,
	table_count: usize,
	lookup_values: OracleId,
	lookup_values_count: usize,
) -> Result<(), anyhow::Error>
where
	U: PackScalar<FS> + Pod,
	F: ExtensionField<FS>,
	FS: TowerField + Pod + Ord,
{
    let now = Instant::now();
	let (multiplicity, prev_index) = populate_require_hints::<FS>(
		builder,
		table,
		table_count,
		lookup_values,
		lookup_values_count,
	)?;
    println!("Populate elapsed: {}", now.elapsed().as_millis());
	let channel = builder.add_channel();
	provide(builder, channel, multiplicity, table, table_count)?;
	require(builder, channel, prev_index, lookup_values, lookup_values_count)?;
	Ok(())
}

#[cfg(test)]
pub mod test_plain_lookup {
	use binius_field::BinaryField32b;
	use binius_maybe_rayon::prelude::*;

	use super::*;
	use crate::transparent;

	const fn into_lookup_claim(x: u8, y: u8, z: u16) -> u32 {
		((z as u32) << 16) | ((y as u32) << 8) | (x as u32)
	}

	fn generate_u8_mul_table() -> Vec<u32> {
		let mut result = Vec::with_capacity(1 << 16);
		for x in 0..=255u8 {
			for y in 0..=255u8 {
				let product = x as u16 * y as u16;
				result.push(into_lookup_claim(x, y, product));
			}
		}
		result
	}

	fn generate_random_u8_mul_claims(vals: &mut [u32]) {
		use rand::Rng;
		vals.par_iter_mut().for_each(|val| {
			let mut rng = rand::thread_rng();
			let x = rng.gen_range(0..=255u8);
			let y = rng.gen_range(0..=255u8);
			let product = x as u16 * y as u16;
			*val = into_lookup_claim(x, y, product);
		});
	}

	pub fn test_u8_mul_lookup(
		builder: &mut ConstraintSystemBuilder,
		log_lookup_count: usize,
	) -> Result<(), anyhow::Error> {
		let table_values = generate_u8_mul_table();
		let table = transparent::make_transparent(
			builder,
			"u8_mul_table",
			bytemuck::cast_slice::<_, BinaryField32b>(&table_values),
		)?;

		let lookup_values =
			builder.add_committed("lookup_values", log_lookup_count, BinaryField32b::TOWER_LEVEL);

		// reduce these if only some table values are valid
		// or only some lookup_values are to be looked up
		let table_count = table_values.len();
		let lookup_values_count = 1 << log_lookup_count;

		if let Some(witness) = builder.witness() {
			let mut lookup_values_col = witness.new_column::<BinaryField32b>(lookup_values);
			let mut_slice = lookup_values_col.as_mut_slice::<u32>();
			generate_random_u8_mul_claims(&mut mut_slice[0..lookup_values_count]);
		}

		provide_require_lookup::<BinaryField32b>(
			builder,
			table,
			table_count,
			lookup_values,
			lookup_values_count,
		)?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use std::time::Instant;

    use binius_core::{fiat_shamir::HasherChallenger, tower::CanonicalTowerFamily};
	use binius_hal::make_portable_backend;
	use binius_hash::compress::Groestl256ByteCompression;
	use binius_math::DefaultEvaluationDomainFactory;
	use groestl_crypto::Groestl256;

	use super::test_plain_lookup;
	use crate::builder::ConstraintSystemBuilder;

	#[test]
	fn test_plain_u8_mul_lookup() {
		let log_lookup_count = 22;

		let log_inv_rate = 1;
		let security_bits = 20;

        let now = Instant::now();
		let proof = {
			let allocator = bumpalo::Bump::new();
			let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);

			test_plain_lookup::test_u8_mul_lookup(&mut builder, log_lookup_count).unwrap();

			let witness = builder.take_witness().unwrap();
			let constraint_system = builder.build().unwrap();
			// validating witness with `validate_witness` is too slow for large transparents like the `table`

			let domain_factory = DefaultEvaluationDomainFactory::default();
			let backend = make_portable_backend();

			binius_core::constraint_system::prove::<
				crate::builder::types::U,
				CanonicalTowerFamily,
				_,
				Groestl256,
				Groestl256ByteCompression,
				HasherChallenger<Groestl256>,
				_,
			>(
				&constraint_system,
				log_inv_rate,
				security_bits,
				&[],
				witness,
				&domain_factory,
				&backend,
			)
			.unwrap()
		};
        let elapsed = now.elapsed();
        println!("Provide-require proof elapsed: {}, proof size: {}", elapsed.as_millis(), proof.get_proof_size());

		// verify
		{
			let mut builder = ConstraintSystemBuilder::new();

			test_plain_lookup::test_u8_mul_lookup(&mut builder, log_lookup_count).unwrap();

			let constraint_system = builder.build().unwrap();

			binius_core::constraint_system::verify::<
				crate::builder::types::U,
				CanonicalTowerFamily,
				Groestl256,
				Groestl256ByteCompression,
				HasherChallenger<Groestl256>,
			>(&constraint_system, log_inv_rate, security_bits, &[], proof)
			.unwrap();
		}
	}
}
