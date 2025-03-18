use std::{array, iter::successors, slice::SliceIndex};

use anyhow::anyhow;
use binius_circuits::{builder::ConstraintSystemBuilder, lasso::lasso};
use binius_core::{
	constraint_system, constraint_system::channel::ChannelId, fiat_shamir::HasherChallenger,
	oracle::OracleId, tower::CanonicalTowerFamily, transparent::powers::Powers,
};
use binius_field::{
	arch::OptimalUnderlier, as_packed_field::PackedType, BinaryField, BinaryField128b,
	BinaryField32b, BinaryField8b, Field, PackedField, PackedFieldIndexable, TowerField,
};
use binius_hal::make_portable_backend;
use binius_hash::compress::Groestl256ByteCompression;
use binius_math::DefaultEvaluationDomainFactory;
use binius_maybe_rayon::prelude::*;
use binius_utils::checked_arithmetics::log2_ceil_usize;
use bytesize::ByteSize;
use groestl_crypto::Groestl256;
use itertools::Either;

type U = OptimalUnderlier;
type F128 = BinaryField128b;
type F32 = BinaryField32b;
type F8 = BinaryField8b;

#[derive(Clone, Debug)]
pub struct ReadOnlyMemory {
	pub mem: Either<usize, (Vec<u8>, Vec<F32>)>,
	channel: ChannelId,
	n_lookups: Vec<usize>,
	lookups_u: Vec<[OracleId; 1]>,
	u_to_t_mappings: Vec<Vec<usize>>,
}

pub struct RomOracle {
	tuple_ptr: OracleId,
	offset: usize,
	u_to_t_index: usize,
}

impl ReadOnlyMemory {
	// This function is just for demonstrating address mutation.
	// Actually it is unnecessary to allow caller mutating address list
	pub fn set_address(&mut self, idx: usize, value: F32) {
		if let Some(l) = self.mem.as_mut().right() {
			l.1[idx] = value;
		}
	}

	pub fn new(builder: &mut ConstraintSystemBuilder, mem: Either<usize, Vec<u8>>) -> Self {
		let channel = builder.add_channel();
		let mem = mem.map_right(|mem| {
			let addresses =
				successors(Some(F32::ONE), |&prev| Some(prev * F32::MULTIPLICATIVE_GENERATOR))
					.take(mem.len())
					.collect();
			(mem, addresses)
		});

		Self {
			mem,
			channel,
			n_lookups: Vec::new(),
			lookups_u: Vec::new(),
			u_to_t_mappings: Vec::new(),
		}
	}

	#[allow(clippy::len_without_is_empty)]
	pub fn len(&self) -> usize {
		self.mem.as_ref().either(|&size| size, |(mem, _)| mem.len())
	}

	pub fn get<I: SliceIndex<[u8]>>(&self, index: I) -> Option<&<I as SliceIndex<[u8]>>::Output> {
		self.mem
			.as_ref()
			.expect_right("ReadOnlyMemory::get() is prover-only")
			.0
			.get(index)
	}

	// This is useful for padding memory chunks, for example for compression functions that operate over fixed-size input/output
	pub fn zero_extend(&mut self, new_len: usize) {
		let (mem, addresses) = self
			.mem
			.as_mut()
			.expect_right("ReadOnlyMemory::zero_extend() is prover_only");

		if new_len <= mem.len() {
			return;
		}

		let first_new_address = addresses
			.last()
			.map_or(F32::ONE, |&last| last * F32::MULTIPLICATIVE_GENERATOR);

		let new_addresses =
			successors(Some(first_new_address), |&prev| Some(prev * F32::MULTIPLICATIVE_GENERATOR))
				.take(new_len - mem.len());

		addresses.extend(new_addresses);
		mem.resize(new_len, 0);
	}

	pub fn mult_address(&self, address: usize) -> Option<F32> {
		self.mem.as_ref().either(
			|&size| {
				Some(F32::MULTIPLICATIVE_GENERATOR.pow(address as u64)).filter(|_| address < size)
			},
			|(_, addresses)| addresses.get(address).copied(),
		)
	}

	pub fn read_byte_oracle(
		&mut self,
		builder: &mut ConstraintSystemBuilder,
		group_name: &str,
		read_ptr: OracleId,
		byte_value: OracleId,
		count: usize,
		offset: usize,
	) -> anyhow::Result<RomOracle> {
		let n_vars = builder.log_rows([read_ptr, byte_value])?;

		let mult_offset = self
			.mult_address(offset)
			.ok_or_else(|| anyhow!("ROM read offset out of range {}", offset))?;

		let tuple_ptr = builder.add_linear_combination(
			format!("{}_offs_{}", group_name, offset),
			n_vars,
			[
				(read_ptr, <F128 as TowerField>::basis(F32::TOWER_LEVEL, 1)? * mult_offset),
				(byte_value, <F128 as TowerField>::basis(F32::TOWER_LEVEL, 0)?),
			],
		)?;

		self.n_lookups.push(count);
		self.lookups_u.push([tuple_ptr]);

		let u_to_t_index = self.u_to_t_mappings.len();
		self.u_to_t_mappings.push(Vec::new());

		Ok(RomOracle {
			tuple_ptr,
			offset,
			u_to_t_index,
		})
	}

	pub fn read_byte_witness<Row>(
		&mut self,
		builder: &mut ConstraintSystemBuilder,
		rows_witness: &[Row],
		rom_oracle: RomOracle,
		dest_addr_getter: impl Fn(&Row) -> usize + Sync,
	) -> anyhow::Result<()>
	where
		Row: Sync,
	{
		let Some(witness) = builder.witness() else {
			return Err(anyhow!("read_byte_witness should not be called in the verifier"));
		};

		let (mem, addresses) = self
			.mem
			.as_ref()
			.expect_right("read_byte_witness() requires ReadOnlyMemory with witness");

		let RomOracle {
			tuple_ptr,
			offset,
			u_to_t_index,
		} = rom_oracle;

		let mut tuple_ptr_column = witness.new_column::<F128>(tuple_ptr);
		let tuple_ptr_column_pod = tuple_ptr_column.as_mut_slice::<u128>();
		let u_to_t_mapping = &mut self.u_to_t_mappings[u_to_t_index];
		u_to_t_mapping.resize(rows_witness.len(), 0);

		(tuple_ptr_column_pod, rows_witness, u_to_t_mapping.as_mut_slice())
			.into_par_iter()
			.try_for_each(|(tuple_dest, row, u_to_t)| -> anyhow::Result<()> {
				let dest_addr = dest_addr_getter(row);
				let read_addr = dest_addr + offset;
				let read_addr_mult = addresses
					.get(read_addr)
					.copied()
					.ok_or_else(|| anyhow!("ROM read address out of range"))?;

				let byte_value = mem[read_addr];

				*u_to_t = read_addr;

				*tuple_dest = (u128::from(F128::from(read_addr_mult)) << (1 << F32::TOWER_LEVEL))
					| (byte_value as u128);

				Ok(())
			})?;

		Ok(())
	}
}

// Given memory written into a witness, this function finalizes constructing input for lasso lookup
// and executes lasso
pub fn build(
	builder: &mut ConstraintSystemBuilder,
	mut rom: ReadOnlyMemory,
) -> anyhow::Result<usize> {
	let size = rom.mem.as_ref().either(|&size| size, |(mem, _)| mem.len());
	let n_vars = log2_ceil_usize(size);

	if rom.mem.is_right() {
		rom.zero_extend(1 << n_vars);
	}

	builder.push_namespace("rom_finalize");

	let rom_addresses = builder.add_transparent(
		"rom_addresses",
		Powers::new(n_vars, F128::from(F32::MULTIPLICATIVE_GENERATOR)),
	)?;
	let rom_bytes = builder.add_committed("rom_bytes", n_vars, F8::TOWER_LEVEL);

	let lookup_t = builder.add_linear_combination(
		"rom_lookup_t",
		n_vars,
		[
			(rom_addresses, <F128 as TowerField>::basis(F32::TOWER_LEVEL, 1)?),
			(rom_bytes, <F128 as TowerField>::basis(F32::TOWER_LEVEL, 0)?),
		],
	)?;

	if let Some((mem, addresses)) = rom.mem.right() {
		let Some(witness) = builder.witness() else {
			todo!();
		};

		let mut rom_addresses_column = witness.new_column::<F32>(rom_addresses);
		let mut rom_bytes_column = witness.new_column::<F8>(rom_bytes);
		let mut lookup_t_column = witness.new_column::<F128>(lookup_t);

		(
			PackedType::<U, F32>::unpack_scalars_mut(rom_addresses_column.packed()),
			rom_bytes_column.as_mut_slice::<u8>(),
			lookup_t_column.as_mut_slice::<u128>(),
			addresses.as_slice(),
			mem.as_slice(),
		)
			.into_par_iter()
			.for_each(|(dest_address, dest_rom_byte, dest_lookup_t, &address, &rom_byte)| {
				*dest_address = address;
				*dest_rom_byte = rom_byte;
				*dest_lookup_t =
					u128::from(F128::from(address)) << (1 << F32::TOWER_LEVEL) | (rom_byte as u128);
			});
	}

	builder.pop_namespace();

	// REVIEW: augment Lasso interface to support arbitrary lookup_t lengths
	lasso::lasso::<F32>(
		builder,
		"rom_lasso",
		&rom.n_lookups,
		&rom.u_to_t_mappings,
		&rom.lookups_u,
		[lookup_t],
		rom.channel,
	)?;

	Ok(1 << n_vars)
}

const LOG_SIZE: usize = 10;
const MEMORY_CHUNKS_NUM: usize = 16;
const MEMORY_CHUNK_SIZE: u8 = 32;

#[derive(Debug)]
pub struct MemorySlice {
	ptr: usize,
}

#[derive(Debug)]
pub struct TraceRow {
	slice: MemorySlice,
	data: [u8; MEMORY_CHUNK_SIZE as usize],
}

fn main() {
	let allocator = bumpalo::Bump::new();
	let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);

	// Random memory. For simplicity here I use multiple chunks (depending in LOG_SIZE value) of the form:
	// [0, 1, 2, 3, ..., MEMORY_CHUNK_SIZE]
	let raw_memory: [u8; 1 << LOG_SIZE] = array::from_fn(|i| (i as u8) % MEMORY_CHUNK_SIZE);

	// Create ROM object for prover (using Either::Right with actual memory)
	let mut memory = ReadOnlyMemory::new(&mut builder, Either::Right(raw_memory.to_vec()));

	let chunk_ptr = 0usize;

	// Generate traces
	let mut trace_rows = vec![];
	let mut chunk_data = vec![];
	for idx in 0..MEMORY_CHUNKS_NUM {
		let mut chunk = [0; MEMORY_CHUNK_SIZE as usize];
		chunk.copy_from_slice(
			memory
				.get(
					chunk_ptr + idx * MEMORY_CHUNK_SIZE as usize
						..chunk_ptr + idx * MEMORY_CHUNK_SIZE as usize + MEMORY_CHUNK_SIZE as usize,
				)
				.unwrap(),
		);

		chunk_data.push(chunk);

		trace_rows.push(TraceRow {
			slice: MemorySlice {
				ptr: chunk_ptr + MEMORY_CHUNK_SIZE as usize * idx,
			},
			data: chunk,
		});
	}

	// populate witness for prover (using Either::Right with actual traces)
	populate_witness_for_lasso_lookup(
		&mut builder,
		&mut memory,
		Either::Right(trace_rows.as_slice()),
	)
	.unwrap();

	// If we uncomment following line, we mutate addresses list at 1st position, which will break
	// chunk <-> address mapping and verification will fail
	//memory.set_address(1, F32::new(1));

	// Execute lasso lookup
	let rom_size = build(&mut builder, memory).unwrap();

	let witness = builder.take_witness().unwrap();
	let prover_cs = builder.build().unwrap();
	//validate_witness(&prover_cs, &vec![], &witness).unwrap();

	// Prover
	let domain_factory = DefaultEvaluationDomainFactory::default();
	let backend = make_portable_backend();

	let proof = constraint_system::prove::<
		U,
		CanonicalTowerFamily,
		_,
		Groestl256,
		Groestl256ByteCompression,
		HasherChallenger<Groestl256>,
		_,
	>(&prover_cs, 1, 100, &vec![], witness, &domain_factory, &backend)
	.unwrap();

	println!("Proof size: {}", ByteSize::b(proof.get_proof_size() as u64));

	// Verifier
	let mut verifier_builder = ConstraintSystemBuilder::new();

	// Create ROM object for verifier (using Either::Left with just expected memory size)
	let mut verifier_rom = ReadOnlyMemory::new(&mut verifier_builder, Either::Left(rom_size));

	// Populate witness for verifier (using Either::Left with just expected length of the traces)
	populate_witness_for_lasso_lookup(
		&mut verifier_builder,
		&mut verifier_rom,
		Either::Left(trace_rows.len()),
	)
	.unwrap();

	// Execute lasso lookup
	let _ = build(&mut verifier_builder, verifier_rom).unwrap();
	let verifier_cs = verifier_builder.build().unwrap();

	constraint_system::verify::<
		U,
		CanonicalTowerFamily,
		Groestl256,
		Groestl256ByteCompression,
		HasherChallenger<Groestl256>,
	>(&verifier_cs, 1, 100, &vec![], proof)
	.unwrap();
}

// The ReadOnlyMemory gadget's API is called here while preparing input for lasso
fn populate_witness_for_lasso_lookup(
	builder: &mut ConstraintSystemBuilder,
	memory: &mut ReadOnlyMemory,
	rows: Either<usize, &[TraceRow]>,
) -> anyhow::Result<(OracleId, [OracleId; MEMORY_CHUNKS_NUM])> {
	let count = rows.either(|count| count, |witness| witness.len());

	let n_vars = log2_ceil_usize(count);

	builder.push_namespace("block_rom_readout");

	let preimage_ptr = builder.add_committed("preimage_ptr", n_vars, F32::TOWER_LEVEL);

	let block_rom_readout = builder.add_committed_multiple::<MEMORY_CHUNKS_NUM>(
		"block_rom_readout",
		n_vars,
		F8::TOWER_LEVEL,
	);

	let rom_oracles = block_rom_readout
		.iter()
		.enumerate()
		.map(|(offset, &byte_value)| {
			memory.read_byte_oracle(
				builder,
				"block_rom_readout_lookup",
				preimage_ptr,
				byte_value,
				count,
				offset,
			)
		})
		.collect::<Result<Vec<_>, _>>()?;

	// We populate witness only for prover (if rows are under Either::Right)
	if let Some(rows) = rows.right() {
		for rom_oracle in rom_oracles {
			memory.read_byte_witness(builder, rows, rom_oracle, |row| row.slice.ptr)?;
		}
		for (j, &column_oracle) in block_rom_readout.iter().enumerate() {
			transpose_rows_f8_u8(builder, rows, column_oracle, |row| Some(row.data[j]))?;
		}

		transpose_rows_f32_f32(builder, rows, preimage_ptr, |row| {
			memory.mult_address(row.slice.ptr)
		})?;
	}

	builder.pop_namespace();

	Ok((preimage_ptr, block_rom_readout))
}

// My suspicious is that these two functions below for transposing rows implement committing memory data "horizontally",
// making overall prove / verify execution more efficient

pub fn transpose_rows_f8_u8(
	builder: &mut ConstraintSystemBuilder,
	rows_witness: &[TraceRow],
	column_oracle: OracleId,
	getter: impl Fn(&TraceRow) -> Option<u8> + Sync,
) -> anyhow::Result<()> {
	let Some(witness) = builder.witness() else {
		todo!();
	};

	let mut column = witness.new_column::<F8>(column_oracle);
	let column_pod = column.as_mut_slice::<u8>();

	column_pod
		.par_iter_mut()
		.zip(rows_witness)
		.try_for_each(|(dest, row)| {
			*dest = getter(row)?;
			Some(())
		})
		.ok_or_else(|| anyhow!("getter failure in transpose_rows()"))?;

	Ok(())
}

pub fn transpose_rows_f32_f32(
	builder: &mut ConstraintSystemBuilder,
	rows_witness: &[TraceRow],
	column_oracle: OracleId,
	getter: impl Fn(&TraceRow) -> Option<F32> + Sync,
) -> anyhow::Result<()> {
	let Some(witness) = builder.witness() else {
		todo!();
	};

	let mut column = witness.new_column::<F32>(column_oracle);
	let column_pod = column.as_mut_slice::<F32>();

	column_pod
		.par_iter_mut()
		.zip(rows_witness)
		.try_for_each(|(dest, row)| {
			*dest = getter(row)?;
			Some(())
		})
		.ok_or_else(|| anyhow!("getter failure in transpose_rows()"))?;

	Ok(())
}
