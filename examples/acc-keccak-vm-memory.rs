/// This is an implementation of the memory' integrity check (using Binius) - a typical task in the domain of the zkVMs.
/// Programs that need to be proven can be viewed as a memory consisted from set of terms
/// (Lean terms) serialized with some format (iXon) and written to some (content-addressable) storage. The integrity property of
/// such memories is usually achieved by including cryptographic hashes of the serialized terms. In this example, we
/// consider some abstract program / memory represented as `N` randomly generated "senseless" terms prepended with Keccak256 hashes
/// (computed out of the circuit) of these terms: [ hash_0 | hash_1 | ... | hash_N | preimage_0 | preimage_1 | ... | preimage_N ].
///
/// At a high level, the proving claim of the integrity check circuit / chip can be expressed as following:
///
/// 1) Every byte in the memory (either some preimage' or some hash' byte) has its position, defined by unique 32-bit pointer,
/// starting from Binius' F32::ONE. Every consequent address is computed by: `next_addr = prev_addr * F32::MULTIPLICATIVE_GENERATOR`.
///
/// 2) Every i-th preimage corresponds to its i-th Keccak256 hash: `hash_i = Keccak256(preimage_i)`, which is implemented as a computing
/// actual Keccak256 hash of the given preimage and comparing it with the expected one (for each preimage / hash tuple).
///
/// Preimages may have different byte sizes. The Keccak256 hash function operates by iterative applying its core transformation which operates
/// over fixed-size inputs and outputs - 25 64-bit words state. If preimage size is smaller or equal to the size of the state, then ultimate value
/// of hash is output of exactly one core transformation output. Otherwise, preimage is divided into chunks and by applying core transformation
/// to each chunk iteratively, the overall hash function state is updated. If final preimage's chunk is smaller than state size, it is padded to the
/// size of the Keccak state.
///
/// Considering hash functions specifics mentioned above, there are two additional notions, important for understanding circuit implementation:
/// `Trace` and `MemorySliceInfo`. Every particular `Trace` contains information about Keccak state before and after applying exactly one core transformation
/// (and, hence, updating its state). Every particular `MemorySliceInfo` contains information about particular preimage pointer, its length and correspondent
/// hash pointer - in order to identify one particular i-th preimage / hash tuple in the overall memory. In the given example, `Trace` can be either "base" one -
/// meaning that it carries value of Keccak state used as ultimate hash value - or it can be "extra" one - meaning that it carries intermediate values of the Keccak
/// state, and there is a "base" `Trace` in the end of the chain that expresses overall processing which happens during hash value computation.
///
/// Given hash functions specifics and notions of `Trace` and `MemorySliceInfo`, one can extend second part of the high-level claim (defined above) to the following:
/// - Every preimage / hash tuple has exactly one `MemorySliceInfo` and could have one ("base") or more ("extra", "extra" ,  ..., "base" ) `Traces`, depending
/// on size of the preimage. There is a direct correlation between one `MemorySliceInfo` and one or more `Traces` for the particular preimage / hash tuple which is enforced.
/// - Every preimage has been consistently padded when necessary (this is obviously applied only for "base" `Traces`).
/// - Every state transition has been performed correctly (given arbitrary `Trace`, either "base" or "extra", this means that applying one core keccak transformation to the
/// pre-state matches gives expected post-state).
use std::{
	array,
	iter::{repeat_n, successors},
	slice::SliceIndex,
};

use anyhow::{anyhow, ensure};
use binius_circuits::{
	builder::{
		types::{F, U},
		ConstraintSystemBuilder,
	},
	keccakf::{keccakf, KeccakfState},
	lasso::lasso,
};
use binius_core::{
	constraint_system,
	constraint_system::channel::ChannelId,
	fiat_shamir::HasherChallenger,
	oracle::OracleId,
	tower::CanonicalTowerFamily,
	transparent::{constant::Constant, powers::Powers},
};
use binius_field::{
	as_packed_field::{PackScalar, PackedType},
	underlier::UnderlierType,
	BinaryField, BinaryField1b, BinaryField32b, BinaryField64b, BinaryField8b, ExtensionField,
	Field, PackedField, PackedFieldIndexable, TowerField,
};
use binius_hal::make_portable_backend;
use binius_hash::groestl::{Groestl256, Groestl256ByteCompression};
use binius_macros::arith_expr;
use binius_maybe_rayon::{
	iter::{Either, IntoParallelIterator},
	prelude::*,
};
use binius_utils::checked_arithmetics::log2_ceil_usize;
use bytemuck::{must_cast, must_cast_mut, Pod};
use bytesize::ByteSize;
use itertools::{chain, izip, Itertools};
use rand::{rngs::OsRng, Rng};
use tiny_keccak::{Hasher, Keccak};

type F64 = BinaryField64b;
type F32 = BinaryField32b;
type F8 = BinaryField8b;
type F1 = BinaryField1b;

/// Read-only memory gadget.
///
/// The prover instantiates it using some abstract memory represented as a vector of bytes (gadget automatically
/// allocates addresses for each memory byte), then writes overall memory data into the witness and
/// finally checks mapping between given byte and address via lasso lookup constraining.
///
/// The verifier can instantiate it using only length of the memory that is expected. Using own instance of constraint
/// system builder, verifier constraints memory (via lasso lookup) to preserve byte <-> address mapping
///
#[derive(Clone, Debug)]
pub struct MemoryGadget {
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

impl MemoryGadget {
	// Instantiates new instance of the MemoryGadget using either memory value (for prover) or just size of expected memory (for verifier)
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
			.expect_right("MemoryGadget::get() is prover-only")
			.0
			.get(index)
	}

	// This is useful for padding memory chunks, for example for compression functions that operate over fixed-size input/output
	pub fn zero_extend(&mut self, new_len: usize) {
		let (mem, addresses) = self
			.mem
			.as_mut()
			.expect_right("MemoryGadget::zero_extend() is prover_only");

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

	// Allows computing expected value of address (represented as F32) for byte at a given position
	pub fn mult_address(&self, address: usize) -> Option<F32> {
		self.mem.as_ref().either(
			|&size| {
				Some(F32::MULTIPLICATIVE_GENERATOR.pow(address as u64)).filter(|_| address < size)
			},
			|(_, addresses)| addresses.get(address).copied(),
		)
	}

	// Put information about particular byte in memory into a lookup to expect it to have specific address (for both prover / verifier)
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
				(read_ptr, <F as TowerField>::basis(F32::TOWER_LEVEL, 1)? * mult_offset),
				(byte_value, <F as TowerField>::basis(F32::TOWER_LEVEL, 0)?),
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

	// Write actual value of memory' byte into witness (only for prover)
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

		let mut tuple_ptr_column = witness.new_column::<F>(tuple_ptr);
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

				*tuple_dest = (u128::from(F::from(read_addr_mult)) << (1 << F32::TOWER_LEVEL))
					| (byte_value as u128);

				Ok(())
			})?;

		Ok(())
	}

	// This function finalizes constructing input for lasso lookup and executes lasso (for both prover and verifier)
	pub fn run_lookup(&mut self, builder: &mut ConstraintSystemBuilder) -> anyhow::Result<usize> {
		let size = self.mem.as_ref().either(|&size| size, |(mem, _)| mem.len());
		let n_vars = log2_ceil_usize(size);

		if self.mem.is_right() {
			self.zero_extend(1 << n_vars);
		}

		builder.push_namespace("rom_finalize");

		let rom_addresses = builder.add_transparent(
			"rom_addresses",
			Powers::new(n_vars, F::from(F32::MULTIPLICATIVE_GENERATOR)),
		)?;
		let rom_bytes = builder.add_committed("rom_bytes", n_vars, F8::TOWER_LEVEL);

		let lookup_t = builder.add_linear_combination(
			"rom_lookup_t",
			n_vars,
			[
				(rom_addresses, <F as TowerField>::basis(F32::TOWER_LEVEL, 1)?),
				(rom_bytes, <F as TowerField>::basis(F32::TOWER_LEVEL, 0)?),
			],
		)?;

		if let Some((mem, addresses)) = self.mem.clone().right() {
			let Some(witness) = builder.witness() else {
				todo!();
			};

			let mut rom_addresses_column = witness.new_column::<F32>(rom_addresses);
			let mut rom_bytes_column = witness.new_column::<F8>(rom_bytes);
			let mut lookup_t_column = witness.new_column::<F>(lookup_t);

			(
				PackedType::<U, F32>::unpack_scalars_mut(rom_addresses_column.packed()),
				rom_bytes_column.as_mut_slice::<u8>(),
				lookup_t_column.as_mut_slice::<u128>(),
				addresses.as_slice(),
				mem.as_slice(),
			)
				.into_par_iter()
				.for_each(
					|(dest_address, dest_rom_byte, dest_lookup_t, &address, &rom_byte)| {
						*dest_address = address;
						*dest_rom_byte = rom_byte;
						*dest_lookup_t = u128::from(F::from(address)) << (1 << F32::TOWER_LEVEL)
							| (rom_byte as u128);
					},
				);
		}

		builder.pop_namespace();

		// REVIEW: augment Lasso interface to support arbitrary lookup_t lengths
		lasso::lasso::<F32>(
			builder,
			"rom_lasso",
			&self.n_lookups,
			&self.u_to_t_mappings,
			&self.lookups_u,
			[lookup_t],
			self.channel,
		)?;

		Ok(1 << n_vars)
	}
}

// [65..] Number of preimages in the memory. The LOG_SIZE / n_vars value is computed over this number, and if it is too small, Binius will panic
const PREIMAGES_NUM: usize = 65;
const HASHES_NUM: usize = PREIMAGES_NUM;
const PREIMAGE_SIZE: usize = 1000;
const HASH_SIZE: usize = 32;

pub struct BaseTraceOracles {
	pre_hash_state: [OracleId; KECCAK_STATE_BYTE_SIZE],
	preimage_offset: OracleId,
	preimage_length: OracleId,
	hash_offset: OracleId,
	single_preimage_absorb: [OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE],
	post_hash_state: [OracleId; KECCAK_STATE_BYTE_SIZE],
}

pub struct ExtraTraceOracles {
	pre_hash_state: [OracleId; KECCAK_STATE_BYTE_SIZE],
	preimage_offset: OracleId,
	preimage_length: OracleId,
	hash_offset: OracleId,
	single_preimage_absorb: [OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE],
	post_hash_state: [OracleId; KECCAK_STATE_BYTE_SIZE],
}

fn main() {
	// prepare random memory
	let mut rng = OsRng;

	let mut preimages = vec![];
	let mut hashes = vec![];

	assert_eq!(HASHES_NUM, PREIMAGES_NUM);
	for _ in 0..HASHES_NUM {
		// generate random preimage
		let preimage: [u8; PREIMAGE_SIZE] = array::from_fn(|_| rng.gen::<u8>());
		preimages.append(&mut preimage.to_vec());

		// calculate Keccak hash out of the circuit
		let mut keccak = Keccak::v256();
		keccak.update(&preimage);

		let mut output = [0; HASH_SIZE];
		keccak.finalize(&mut output);
		hashes.append(&mut output.to_vec());
	}
	let raw_memory = [hashes, preimages].concat();

	// prover
	let allocator = bumpalo::Bump::new();
	let mut builder_prover = ConstraintSystemBuilder::new_with_witness(&allocator);

	// prepare Memory gadget for prover using memory data (note: Either::Right(raw_memory))
	let mut memory_prover = MemoryGadget::new(&mut builder_prover, Either::Right(raw_memory));

	// prepare IntegrityCheck Gadget
	let mut integrity_check_gadget = IntegrityCheckGadget::new();

	let mut hash_offset = 0usize;
	let mut preimage_offset = HASH_SIZE * HASHES_NUM;

	// Load memory data into IntegrityCheck Gadget. This is a stage of creating traces
	for _ in 0..HASHES_NUM {
		integrity_check_gadget
			.absorb_single_memory_chunk(
				&mut memory_prover,
				// for each (preimage / hash) tuple prover also submits offsets in memory for preimage / hash (and size of preimage)
				MemorySliceInfo {
					preimage_offset,
					preimage_length: PREIMAGE_SIZE,
					hash_offset,
				},
			)
			.unwrap();

		preimage_offset += PREIMAGE_SIZE;
		hash_offset += HASH_SIZE;
	}

	// The first part of the claim is proving the mapping between memory bytes and allocated addresses

	let (padded_memory_size, base_trace_oracles_p, extra_trace_oracles_p) =
		integrity_check_gadget.memory_lookup_prover(&mut memory_prover, &mut builder_prover);

	// The second part of the claim is enforcing that created traces are "synchronized" with the slices (information about preimage / hash offsets).
	// Currently in this example, for simplicity, there are only so-called "base" trace and slices, but if size of preimage is too big
	// to be processed by a single core keccak transformation, there could be additional "recursive" traces and slices that need to be in-sync too.
	integrity_check_gadget.trace_slice_correlation_prover(
		&mut memory_prover,
		&mut builder_prover,
		&base_trace_oracles_p,
		extra_trace_oracles_p.as_ref(),
	);

	// Third part of the claim is enforcing that padding has been correctly applied, and we will later hash in-circuit what is actually expected to be hashed
	// (and then compared to the computed out-of-circuit hash)
	let (
		padding_values_oracles,
		packed_selector_u_oracles,
		padded_absorbed_oracles,
		padded_absorbed_extra_oracles,
	) = integrity_check_gadget.padding_consistency_prover(
		&mut builder_prover,
		&base_trace_oracles_p,
		extra_trace_oracles_p.as_ref(),
	);

	// TODO: figure out this part of a claim in more details
	integrity_check_gadget.padding_lookup_prover(
		&mut memory_prover,
		&mut builder_prover,
		padding_values_oracles,
		packed_selector_u_oracles,
		base_trace_oracles_p.preimage_length,
	);

	// Final part of a claim is applying keccak core transformation to the preimages from the memory and compare the computed hash with expected one
	integrity_check_gadget.keccak_state_transition_prover(
		&mut builder_prover,
		padded_absorbed_oracles,
		padded_absorbed_extra_oracles,
		&base_trace_oracles_p,
		extra_trace_oracles_p.as_ref(),
	);

	let witness = builder_prover.take_witness().unwrap();
	let cs = builder_prover.build().unwrap();

	let backend = make_portable_backend();

	let proof = constraint_system::prove::<
		U,
		CanonicalTowerFamily,
		Groestl256,
		Groestl256ByteCompression,
		HasherChallenger<Groestl256>,
		_,
	>(&cs, 1usize, 100usize, &vec![], witness, &backend)
	.unwrap();

	println!("Proof size: {}", ByteSize::b(proof.get_proof_size() as u64));

	// verifier
	let mut verifier_builder = ConstraintSystemBuilder::new();
	let mut memory_gadget =
		MemoryGadget::new(&mut verifier_builder, Either::Left(padded_memory_size));

	let (base_trace_oracles_v, extra_trace_oracles_v) =
		integrity_check_gadget.memory_lookup_verifier(&mut memory_gadget, &mut verifier_builder);

	integrity_check_gadget.trace_slice_correlation_verifier(
		&mut verifier_builder,
		&base_trace_oracles_v,
		extra_trace_oracles_v.as_ref(),
	);

	let (
		padding_values_oracles,
		packed_selector_u_oracles,
		padded_absorbed_oracles,
		padded_absorbed_extra_oracles,
	) = integrity_check_gadget.padding_consistency_verifier(
		&mut verifier_builder,
		&base_trace_oracles_v,
		extra_trace_oracles_v.as_ref(),
	);

	integrity_check_gadget.padding_lookup_verifier(
		&mut verifier_builder,
		padding_values_oracles,
		packed_selector_u_oracles,
		base_trace_oracles_v.preimage_length,
	);

	integrity_check_gadget.keccak_state_transition_verifier(
		&mut verifier_builder,
		padded_absorbed_oracles,
		padded_absorbed_extra_oracles,
		&base_trace_oracles_v,
		extra_trace_oracles_v.as_ref(),
	);

	let cs = verifier_builder.build().unwrap();
	constraint_system::verify::<
		U,
		CanonicalTowerFamily,
		Groestl256,
		Groestl256ByteCompression,
		HasherChallenger<Groestl256>,
	>(&cs, 1usize, 100usize, &vec![], proof)
	.unwrap();
}

#[derive(Debug, Clone)]
pub struct MemorySliceInfo {
	pub hash_offset: usize,
	pub preimage_offset: usize,
	pub preimage_length: usize,
}

const KECCAK_STATE_BYTE_SIZE: usize = 200;
const SINGLE_PREIMAGE_ABSORB_BYTE_SIZE: usize = 136;

#[derive(Debug, Clone)]
pub struct TraceRow {
	pub slice: MemorySliceInfo,
	pub pre_hash_state: [u8; KECCAK_STATE_BYTE_SIZE],
	pub post_hash_state: [u8; KECCAK_STATE_BYTE_SIZE],
	pub preimage_data_absorbed: [u8; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE],
	pub padded_absorbed: [u8; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE],
}

/// IntegrityCheck Gadget based on Keccak256 hash function.
///
/// This is a gadget that implements proving claim for memory integrity checking.
/// Prover needs to load memory data into the witness and then sequentially call API functions that enforce
/// particular parts of the claim.
///
/// Verifier needs to submit only expected sizes of memory and traces and then also sequentially call API functions that enforce claim.
#[derive(Debug, Clone)]
pub struct IntegrityCheckGadget {
	pub base_traces: Vec<TraceRow>,
	// If preimage size is smaller than SINGLE_PREIMAGE_ABSORB_BYTE_SIZE (e.g. exactly 1 core keccak
	// transformation is sufficient to get the ultimate hash value), extra traces are empty.
	// Otherwise, core keccak transformation needs to mutate inner hash state multiple times,
	// so extra traces contain information for those extra core keccak transformations.
	pub extra_traces: Vec<TraceRow>,
	pub slices: Vec<MemorySliceInfo>,
}

impl IntegrityCheckGadget {
	#[allow(clippy::new_without_default)]
	pub fn new() -> Self {
		IntegrityCheckGadget {
			base_traces: vec![],
			extra_traces: vec![],
			slices: vec![],
		}
	}

	////////////////////////////////////////////////////////////////////////////////////
	////// PROVER
	////////////////////////////////////////////////////////////////////////////////////

	// Loads memory data into the witness
	pub fn absorb_single_memory_chunk(
		&mut self,
		memory: &mut MemoryGadget,
		slice_info: MemorySliceInfo,
	) -> anyhow::Result<()> {
		ensure!(
			slice_info.preimage_offset < memory.len(),
			"preimage offset is not in memory range"
		);
		ensure!(
			slice_info.preimage_offset + slice_info.preimage_length <= memory.len(),
			"preimage length is not in memory range"
		);
		ensure!(
			slice_info.hash_offset + HASH_SIZE <= memory.len(),
			"hash offset is not in memory range"
		);

		self.slices.push(slice_info.clone());

		// we should always have enough memory for absorbing
		let preimage_chunks_length = slice_info.preimage_length / SINGLE_PREIMAGE_ABSORB_BYTE_SIZE;
		memory.zero_extend(
			slice_info.preimage_offset
				+ SINGLE_PREIMAGE_ABSORB_BYTE_SIZE * (preimage_chunks_length + 1),
		);

		let mut pre_hash_state = [0; KECCAK_STATE_BYTE_SIZE];

		for preimage_chunk_idx in 0..=preimage_chunks_length {
			let preimage_offset =
				slice_info.preimage_offset + preimage_chunk_idx * SINGLE_PREIMAGE_ABSORB_BYTE_SIZE;
			let preimage_length =
				slice_info.preimage_length - preimage_chunk_idx * SINGLE_PREIMAGE_ABSORB_BYTE_SIZE;

			let slice = MemorySliceInfo {
				hash_offset: slice_info.hash_offset,
				preimage_offset,
				preimage_length,
			};

			let mut preimage_data_absorbed = [0; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE];
			preimage_data_absorbed.copy_from_slice(
				memory
					.get(preimage_offset..preimage_offset + SINGLE_PREIMAGE_ABSORB_BYTE_SIZE)
					.expect("couldn't read preimage data from memory"),
			);

			// apply padding to the processed preimage chunk if necessary
			let mut padded_absorbed = [0; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE];
			if preimage_length < SINGLE_PREIMAGE_ABSORB_BYTE_SIZE {
				padded_absorbed[..preimage_length]
					.copy_from_slice(&preimage_data_absorbed[..preimage_length]);
				padded_absorbed[preimage_length] ^= 0x01;
				*padded_absorbed.last_mut().expect("last element is None") ^= 0x80;
			} else {
				padded_absorbed.copy_from_slice(&preimage_data_absorbed);
			}

			izip!(&mut padded_absorbed, &pre_hash_state).for_each(|(dest, src)| *dest ^= src);

			let mut post_hash_state = [0u64; KECCAK_STATE_BYTE_SIZE / 8];
			let post_hash_state_u8 =
				must_cast_mut::<_, [u8; KECCAK_STATE_BYTE_SIZE]>(&mut post_hash_state);
			post_hash_state_u8[..SINGLE_PREIMAGE_ABSORB_BYTE_SIZE]
				.copy_from_slice(&padded_absorbed);
			post_hash_state_u8[SINGLE_PREIMAGE_ABSORB_BYTE_SIZE..]
				.copy_from_slice(&pre_hash_state[SINGLE_PREIMAGE_ABSORB_BYTE_SIZE..]);
			tiny_keccak::keccakf(&mut post_hash_state);
			let post_hash_state = must_cast(post_hash_state);

			let trace = TraceRow {
				slice,
				pre_hash_state,
				post_hash_state,
				preimage_data_absorbed,
				padded_absorbed,
			};

			if preimage_chunk_idx == preimage_chunks_length {
				// pre-/post-hash states of last core keccak transformation
				// before getting final hash - base trace
				self.base_traces.push(trace);
			} else {
				// pre-/post-hash states for each core keccak transformation (up to the last one)
				// before getting final hash - extra traces
				self.extra_traces.push(trace);
			}

			// for the next iteration of "long" (greater than SINGLE_PREIMAGE_ABSORB_BYTE_SIZE) preimage processing,
			// we need to apply core keccak transformation to a state updated on this iteration
			pre_hash_state = post_hash_state;
		}

		Ok(())
	}

	pub fn memory_lookup_prover(
		&mut self,
		memory_prover: &mut MemoryGadget,
		builder_prover: &mut ConstraintSystemBuilder,
	) -> (usize, BaseTraceOracles, Option<ExtraTraceOracles>) {
		builder_prover.push_namespace("memory_lookup_prover");

		fn inner(
			name: impl ToString,
			memory_prover: &mut MemoryGadget,
			builder_prover: &mut ConstraintSystemBuilder,
			traces: &Vec<TraceRow>,
		) -> (
			[OracleId; KECCAK_STATE_BYTE_SIZE],
			OracleId,
			OracleId,
			OracleId,
			[OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE],
			[OracleId; KECCAK_STATE_BYTE_SIZE],
		) {
			builder_prover.push_namespace(name);

			let count = traces.len();
			let n_vars = log2_ceil_usize(count);

			let preimage_offset =
				builder_prover.add_committed("preimage_offset", n_vars, F32::TOWER_LEVEL);
			let single_preimage_absorb = builder_prover
				.add_committed_multiple::<SINGLE_PREIMAGE_ABSORB_BYTE_SIZE>(
					"single_preimage_absorb",
					n_vars,
					F8::TOWER_LEVEL,
				);

			let preimage_oracles = single_preimage_absorb
				.iter()
				.enumerate()
				.map(|(offset, &byte_value)| {
					memory_prover.read_byte_oracle(
						builder_prover,
						"single_preimage_absorb_lookup",
						preimage_offset,
						byte_value,
						count,
						offset,
					)
				})
				.collect::<Result<Vec<_>, _>>()
				.unwrap();

			for preimage_oracle in preimage_oracles {
				memory_prover
					.read_byte_witness(builder_prover, &traces, preimage_oracle, |row| {
						row.slice.preimage_offset
					})
					.unwrap();
			}

			for (j, &column_oracle) in single_preimage_absorb.iter().enumerate() {
				transpose_rows::<F8, _, _>(builder_prover, &traces, column_oracle, |row| {
					Some(row.preimage_data_absorbed[j])
				})
				.unwrap();
			}

			transpose_rows::<F32, _, F32>(builder_prover, &traces, preimage_offset, |row| {
				memory_prover.mult_address(row.slice.preimage_offset)
			})
			.unwrap();

			// Prepare lookup input for hashes
			let pre_hash_state = builder_prover.add_committed_multiple::<KECCAK_STATE_BYTE_SIZE>(
				"pre_hash_state",
				n_vars,
				F8::TOWER_LEVEL,
			);
			let post_hash_state = builder_prover.add_committed_multiple::<KECCAK_STATE_BYTE_SIZE>(
				"post_hash_state",
				n_vars,
				F8::TOWER_LEVEL,
			);
			let hash_offset = builder_prover.add_committed("hash_offset", n_vars, F32::TOWER_LEVEL);
			let preimage_length =
				builder_prover.add_committed("preimage_length", n_vars, F32::TOWER_LEVEL);

			for (j, &column_oracle) in pre_hash_state.iter().enumerate() {
				transpose_rows::<F8, _, u8>(builder_prover, &traces, column_oracle, |row| {
					Some(row.pre_hash_state[j])
				})
				.unwrap();
			}

			for (j, &column_oracle) in post_hash_state.iter().enumerate() {
				transpose_rows::<F8, _, u8>(builder_prover, &traces, column_oracle, |row| {
					Some(row.post_hash_state[j])
				})
				.unwrap();
			}

			transpose_rows::<F32, _, F32>(builder_prover, &traces, hash_offset, |row| {
				memory_prover.mult_address(row.slice.hash_offset)
			})
			.unwrap();
			transpose_rows::<F32, _, F32>(builder_prover, &traces, preimage_length, |row| {
				memory_prover.mult_address(row.slice.preimage_length)
			})
			.unwrap();

			builder_prover.pop_namespace();
			(
				pre_hash_state,
				preimage_offset,
				preimage_length,
				hash_offset,
				single_preimage_absorb,
				post_hash_state,
			)
		}

		// Base traces processing
		let (
			pre_hash_state,
			preimage_offset,
			preimage_length,
			hash_offset,
			single_preimage_absorb,
			post_hash_state,
		) = inner("base-traces", memory_prover, builder_prover, &self.base_traces);

		let hash_oracles = post_hash_state[..HASH_SIZE]
			.iter()
			.enumerate()
			.map(|(offset, &byte_value)| {
				memory_prover.read_byte_oracle(
					builder_prover,
					"hash_squeeze_rom_read_lookup",
					hash_offset,
					byte_value,
					self.base_traces.len(),
					offset,
				)
			})
			.collect::<Result<Vec<_>, _>>()
			.unwrap();

		for rom_oracle in hash_oracles {
			memory_prover
				.read_byte_witness(builder_prover, &self.base_traces, rom_oracle, |row| {
					row.slice.hash_offset
				})
				.unwrap();
		}

		// Extra traces processing
		let extra_trace_oracles = if self.extra_traces.len() > 0 {
			let (
				pre_hash_state,
				preimage_offset,
				preimage_length,
				hash_offset,
				single_preimage_absorb,
				post_hash_state,
			) = inner("extra-traces", memory_prover, builder_prover, &self.extra_traces);
			Some(ExtraTraceOracles {
				pre_hash_state,
				preimage_offset,
				preimage_length,
				hash_offset,
				single_preimage_absorb,
				post_hash_state,
			})
		} else {
			None
		};

		let memory_size = memory_prover.run_lookup(builder_prover).unwrap();

		builder_prover.pop_namespace();

		(
			memory_size,
			BaseTraceOracles {
				pre_hash_state,
				preimage_offset,
				preimage_length,
				hash_offset,
				single_preimage_absorb,
				post_hash_state,
			},
			extra_trace_oracles,
		)
	}

	pub fn trace_slice_correlation_prover(
		&mut self,
		memory_prover: &mut MemoryGadget,
		builder_prover: &mut ConstraintSystemBuilder,
		base_trace_oracles: &BaseTraceOracles,
		extra_trace_oracles: Option<&ExtraTraceOracles>,
	) {
		builder_prover.push_namespace("trace_slice_correlation_prover");

		// Base traces processing
		let count = self.base_traces.len();
		let n_vars = log2_ceil_usize(count);

		let packed_pre_hash_state = pack_oracles(
			builder_prover,
			"packed_pre_hash_state",
			n_vars,
			F8::TOWER_LEVEL,
			base_trace_oracles.pre_hash_state,
		)
		.unwrap();

		pack_witness(
			builder_prover,
			&self.base_traces,
			&packed_pre_hash_state,
			F8::TOWER_LEVEL,
			|row| row.pre_hash_state.into_iter(),
		);

		let channel = builder_prover.add_channel();

		builder_prover
			.receive(
				channel,
				count,
				packed_pre_hash_state.into_iter().chain([
					base_trace_oracles.preimage_offset,
					base_trace_oracles.preimage_length,
					base_trace_oracles.hash_offset,
				]),
			)
			.unwrap();

		let preimage_offset =
			builder_prover.add_committed("preimage_offset", n_vars, F32::TOWER_LEVEL);
		let preimage_length =
			builder_prover.add_committed("preimage_length", n_vars, F32::TOWER_LEVEL);
		let hash_offset = builder_prover.add_committed("hash_offset", n_vars, F32::TOWER_LEVEL);

		let zero_column = builder_prover
			.add_transparent("zero_column", Constant::new(n_vars, F::ZERO))
			.unwrap();
		transpose_rows::<F, _, _>(builder_prover, &self.slices, zero_column, |_slice| Some(0))
			.unwrap();

		transpose_rows::<F32, _, _>(builder_prover, &self.slices, preimage_offset, |slice| {
			memory_prover.mult_address(slice.preimage_offset)
		})
		.unwrap();

		transpose_rows::<F32, _, _>(builder_prover, &self.slices, preimage_length, |slice| {
			memory_prover.mult_address(slice.preimage_length)
		})
		.unwrap();

		transpose_rows::<F32, _, _>(builder_prover, &self.slices, hash_offset, |slice| {
			memory_prover.mult_address(slice.hash_offset)
		})
		.unwrap();

		let per_lincom = 1 << (F::TOWER_LEVEL - F8::TOWER_LEVEL);
		let mut flush_oracles = vec![zero_column; KECCAK_STATE_BYTE_SIZE.div_ceil(per_lincom)];
		flush_oracles.extend([preimage_offset, preimage_length, hash_offset]);

		builder_prover.send(channel, count, flush_oracles).unwrap();

		// Extra traces processing
		if self.extra_traces.len() > 0 {
			let extra_trace_oracles = extra_trace_oracles.unwrap();

			let count_extra = self.extra_traces.len();
			let n_vars_extra = log2_ceil_usize(count_extra);
			let hash_r_mult_stride =
				F32::MULTIPLICATIVE_GENERATOR.pow(SINGLE_PREIMAGE_ABSORB_BYTE_SIZE as u64);
			let hash_r_mult_stride_inverse =
				hash_r_mult_stride.invert().expect("nonzero by definition");

			let next_preimage_offset_extra = builder_prover
				.add_linear_combination(
					"next_preimage_offset",
					n_vars_extra,
					[(extra_trace_oracles.preimage_offset, hash_r_mult_stride.into())],
				)
				.unwrap();

			let next_preimage_length_extra = builder_prover
				.add_linear_combination(
					"next_remaining_bytes",
					n_vars_extra,
					[(extra_trace_oracles.preimage_length, hash_r_mult_stride_inverse.into())],
				)
				.unwrap();

			let packed_pre_hash_state_extra = pack_oracles(
				builder_prover,
				"packed_pre_hash_state_extra",
				n_vars_extra,
				F8::TOWER_LEVEL,
				extra_trace_oracles.pre_hash_state,
			)
			.unwrap();

			let packed_post_hash_state_extra = pack_oracles(
				builder_prover,
				"packed_post_hash_state_extra",
				n_vars_extra,
				F8::TOWER_LEVEL,
				extra_trace_oracles.post_hash_state,
			)
			.unwrap();

			transpose_rows::<F32, _, _>(
				builder_prover,
				&self.extra_traces,
				next_preimage_offset_extra,
				|row| {
					memory_prover
						.mult_address(row.slice.preimage_offset + SINGLE_PREIMAGE_ABSORB_BYTE_SIZE)
				},
			)
			.unwrap();

			transpose_rows::<F32, _, _>(
				builder_prover,
				&self.extra_traces,
				next_preimage_length_extra,
				|row| {
					memory_prover
						.mult_address(row.slice.preimage_length - SINGLE_PREIMAGE_ABSORB_BYTE_SIZE)
				},
			)
			.unwrap();

			pack_witness(
				builder_prover,
				&self.extra_traces,
				&packed_pre_hash_state_extra,
				F8::TOWER_LEVEL,
				|row| row.pre_hash_state.into_iter(),
			);

			pack_witness(
				builder_prover,
				&self.extra_traces,
				&packed_post_hash_state_extra,
				F8::TOWER_LEVEL,
				|row| row.post_hash_state.into_iter(),
			);

			builder_prover
				.receive(
					channel,
					count_extra,
					packed_pre_hash_state_extra.into_iter().chain([
						extra_trace_oracles.preimage_offset,
						extra_trace_oracles.preimage_length,
						extra_trace_oracles.hash_offset,
					]),
				)
				.unwrap();

			builder_prover
				.send(
					channel,
					count_extra,
					packed_post_hash_state_extra.into_iter().chain([
						next_preimage_offset_extra,
						next_preimage_length_extra,
						extra_trace_oracles.hash_offset,
					]),
				)
				.unwrap();
		}

		builder_prover.pop_namespace();
	}

	pub fn padding_consistency_prover(
		&mut self,
		builder_prover: &mut ConstraintSystemBuilder,
		base_trace_oracles: &BaseTraceOracles,
		extra_trace_oracles: Option<&ExtraTraceOracles>,
	) -> (
		[OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE],
		Vec<OracleId>,
		[OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE],
		Option<[OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE]>,
	) {
		builder_prover.push_namespace("padding_consistency_prover");

		// Base traces processing
		let count = self.base_traces.len();
		let n_vars = log2_ceil_usize(count);

		let selector = builder_prover.add_committed_multiple::<SINGLE_PREIMAGE_ABSORB_BYTE_SIZE>(
			"selector",
			n_vars,
			F1::TOWER_LEVEL,
		);
		let packed_selector_u =
			pack_oracles(builder_prover, "packed_selector_u", n_vars, F1::TOWER_LEVEL, selector)
				.unwrap();

		transpose_scalar_matrix(builder_prover, &self.base_traces, selector, |row| {
			selector_fn(row.slice.preimage_length)
		})
		.unwrap();

		pack_witness(
			builder_prover,
			&self.base_traces,
			&packed_selector_u,
			F1::TOWER_LEVEL,
			|row| selector_fn(row.slice.preimage_length).map(u8::from),
		);

		let padded_absorbed = builder_prover
			.add_committed_multiple::<SINGLE_PREIMAGE_ABSORB_BYTE_SIZE>(
				"padded_absorbed",
				n_vars,
				F8::TOWER_LEVEL,
			);
		transpose_scalar_matrix(builder_prover, &self.base_traces, padded_absorbed, |row| {
			row.padded_absorbed.into_iter().map(F8::new)
		})
		.unwrap();

		let padding_values = builder_prover
			.add_committed_multiple::<SINGLE_PREIMAGE_ABSORB_BYTE_SIZE>(
				"padding_values",
				n_vars,
				F8::TOWER_LEVEL,
			);

		transpose_scalar_matrix(builder_prover, &self.base_traces, padding_values, |row| {
			padding_values_fn(row.slice.preimage_length)
		})
		.unwrap();

		let padding_consistency = arith_expr!(
			[padded, pre_hash_state, selector, padding_value, rom_read] =
				padded + pre_hash_state + selector * rom_read + (1 - selector) * padding_value
		);

		izip!(
			&padded_absorbed,
			&base_trace_oracles.pre_hash_state,
			&selector,
			&padding_values,
			&base_trace_oracles.single_preimage_absorb
		)
		.enumerate()
		.for_each(
			|(i, (&padded, &pre_hash_state, &selector, &padding_value, &absorbed_byte))| {
				builder_prover.assert_zero(
					format!("padding_consistency_{}", i),
					[
						padded,
						pre_hash_state,
						selector,
						padding_value,
						absorbed_byte,
					],
					padding_consistency.clone().convert_field(),
				)
			},
		);

		// Extra traces processing
		let padded_absorbed_extra = if self.extra_traces.len() > 0 {
			let extra_trace_oracles = extra_trace_oracles.unwrap();

			let count_extra = self.extra_traces.len();
			let n_vars_extra = log2_ceil_usize(count_extra);

			let padded_absorbed_extra: [OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE] =
				array::from_fn(|i| {
					builder_prover
						.add_linear_combination(
							format!("padded_absorbed_extra_{}", i),
							n_vars_extra,
							[
								(extra_trace_oracles.single_preimage_absorb[i], F::ONE),
								(extra_trace_oracles.pre_hash_state[i], F::ONE),
							],
						)
						.expect(
							"block rom read and pre hash state oracles newly added; \
                     all of them have ceil(log2(count)) variables.",
						)
				});

			transpose_scalar_matrix(
				builder_prover,
				&self.extra_traces,
				padded_absorbed_extra,
				|row| row.padded_absorbed.into_iter().map(F8::new),
			)
			.unwrap();

			Some(padded_absorbed_extra)
		} else {
			None
		};

		builder_prover.pop_namespace();

		(padding_values, packed_selector_u, padded_absorbed, padded_absorbed_extra)
	}

	pub fn padding_lookup_prover(
		&mut self,
		memory_prover: &mut MemoryGadget,
		builder_prover: &mut ConstraintSystemBuilder,
		padding_values: [OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE],
		packed_selector_u: Vec<OracleId>,
		preimage_length_oracle: OracleId,
	) {
		builder_prover.push_namespace("padding_lookup_prover");

		// Base traces processing (padding is not applicable to the extra traces by definition)
		let count = self.base_traces.len();
		let n_vars = log2_ceil_usize(count);

		let lookup_n_vars = log2_ceil_usize(SINGLE_PREIMAGE_ABSORB_BYTE_SIZE);

		let preimage_length_t =
			builder_prover.add_committed("preimage_length_t", lookup_n_vars, F32::TOWER_LEVEL);

		if let Some(witness) = builder_prover.witness() {
			let mut preimage_length_t_column = witness.new_column::<F32>(preimage_length_t);
			let preimage_length_t_scalars =
				PackedType::<U, F32>::unpack_scalars_mut(preimage_length_t_column.packed());

			preimage_length_t_scalars
				.into_par_iter()
				.enumerate()
				.for_each(|(i, preimage_length_mult)| {
					let preimage_length = i % SINGLE_PREIMAGE_ABSORB_BYTE_SIZE;
					*preimage_length_mult = memory_prover
						.mult_address(preimage_length)
						.expect("ROM padded to at least a block");
				});
		}

		let packed_padding_values_u = pack_oracles(
			builder_prover,
			"packed_padding_values_u",
			n_vars,
			F8::TOWER_LEVEL,
			padding_values,
		)
		.unwrap();
		pack_witness(
			builder_prover,
			&self.base_traces,
			&packed_padding_values_u,
			F8::TOWER_LEVEL,
			|row| padding_values_fn(row.slice.preimage_length).map(u8::from),
		);

		let selector_t = builder_prover.add_committed_multiple::<SINGLE_PREIMAGE_ABSORB_BYTE_SIZE>(
			"selector_t",
			lookup_n_vars,
			F1::TOWER_LEVEL,
		);
		let packed_selector_t = pack_oracles(
			builder_prover,
			"packed_selector_t",
			lookup_n_vars,
			F1::TOWER_LEVEL,
			selector_t,
		)
		.unwrap();

		let table_rows = (0..1 << lookup_n_vars).collect_vec();
		transpose_scalar_matrix(builder_prover, &table_rows, selector_t, |&row_index| {
			selector_fn(row_index % SINGLE_PREIMAGE_ABSORB_BYTE_SIZE)
		})
		.unwrap();

		pack_witness(
			builder_prover,
			&table_rows,
			&packed_selector_t,
			F1::TOWER_LEVEL,
			|&row_index| selector_fn(row_index % SINGLE_PREIMAGE_ABSORB_BYTE_SIZE).map(u8::from),
		);

		let padding_values_t = builder_prover
			.add_committed_multiple::<SINGLE_PREIMAGE_ABSORB_BYTE_SIZE>(
				"padding_values_t",
				lookup_n_vars,
				F8::TOWER_LEVEL,
			);
		transpose_scalar_matrix(builder_prover, &table_rows, padding_values_t, |&row_index| {
			padding_values_fn(row_index % SINGLE_PREIMAGE_ABSORB_BYTE_SIZE)
		})
		.unwrap();

		let packed_padding_values_t = pack_oracles(
			builder_prover,
			"packed_padding_values_t",
			lookup_n_vars,
			F8::TOWER_LEVEL,
			padding_values_t,
		)
		.unwrap();
		pack_witness(
			builder_prover,
			&table_rows,
			&packed_padding_values_t,
			F8::TOWER_LEVEL,
			|&row_index| {
				padding_values_fn(row_index % SINGLE_PREIMAGE_ABSORB_BYTE_SIZE).map(u8::from)
			},
		);

		let lookup_u = chain!(packed_selector_u, packed_padding_values_u, [preimage_length_oracle])
			.collect_vec();

		let lookup_t =
			chain!(packed_selector_t, packed_padding_values_t, [preimage_length_t]).collect_vec();

		let padding_lasso_channel = builder_prover.add_channel();
		let mut u_to_t_mapping = Vec::new();
		u_to_t_mapping.extend(
			self.base_traces
				.iter()
				.map(|row| row.slice.preimage_length % SINGLE_PREIMAGE_ABSORB_BYTE_SIZE),
		);

		lasso::lasso::<F32>(
			builder_prover,
			"padding_lasso",
			&[count],
			&[u_to_t_mapping],
			&[lookup_u],
			&lookup_t,
			padding_lasso_channel,
		)
		.unwrap();

		builder_prover.pop_namespace();
	}

	pub fn keccak_state_transition_prover(
		&mut self,
		builder_prover: &mut ConstraintSystemBuilder,
		padded_absorbed: [OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE],
		padded_absorbed_extra: Option<[OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE]>,
		base_trace_oracles: &BaseTraceOracles,
		extra_trace_oracles: Option<&ExtraTraceOracles>,
	) {
		builder_prover.push_namespace("keccak_state_transition_prover");

		// Base traces processing
		let count_base = self.base_traces.len();
		let n_vars_base = log2_ceil_usize(count_base);

		let keccakf_channel = builder_prover.add_channel();

		let keccakf_push_body = pack_oracles(
			builder_prover,
			"keccakf_push_body",
			n_vars_base,
			F8::TOWER_LEVEL,
			chain!(
				&padded_absorbed,
				&base_trace_oracles.pre_hash_state[SINGLE_PREIMAGE_ABSORB_BYTE_SIZE..],
				&base_trace_oracles.post_hash_state
			)
			.copied(),
		)
		.unwrap();

		pack_witness(
			builder_prover,
			&self.base_traces,
			&keccakf_push_body,
			F8::TOWER_LEVEL,
			|row| {
				chain!(
					&row.padded_absorbed,
					&row.pre_hash_state[SINGLE_PREIMAGE_ABSORB_BYTE_SIZE..],
					&row.post_hash_state
				)
				.copied()
			},
		);

		builder_prover
			.send(keccakf_channel, count_base, keccakf_push_body)
			.unwrap();

		// Both Base and Extra traces processing
		if self.extra_traces.len() > 0 {
			let padded_absorbed_extra = padded_absorbed_extra.unwrap();
			let extra_trace_oracles = extra_trace_oracles.unwrap();

			let count_total = self.base_traces.len() + self.extra_traces.len();
			let n_vars_total = log2_ceil_usize(count_total);
			let mut states = chain!(&self.base_traces, &self.extra_traces)
				.into_iter()
				.map(|row| {
					let mut absorbed_pre_hash_state = row.pre_hash_state;
					absorbed_pre_hash_state[..SINGLE_PREIMAGE_ABSORB_BYTE_SIZE]
						.copy_from_slice(&row.padded_absorbed);
					KeccakfState(must_cast(absorbed_pre_hash_state))
				})
				.collect_vec();

			states.resize_with(1 << n_vars_total, KeccakfState::default);

			let keccakf_oracles = keccakf(builder_prover, &Some(states), n_vars_total).unwrap();

			let keccakf_pull_body = pack_oracles(
				builder_prover,
				"keccakf_pull_body",
				n_vars_total,
				F64::TOWER_LEVEL,
				chain!(&keccakf_oracles.input, &keccakf_oracles.output).copied(),
			)
			.unwrap();

			let mut input_output = chain!(&self.base_traces, &self.extra_traces)
				.into_iter()
				.map(|row| {
					let mut absorbed_pre_hash_state = row.pre_hash_state;
					absorbed_pre_hash_state[..SINGLE_PREIMAGE_ABSORB_BYTE_SIZE]
						.copy_from_slice(&row.padded_absorbed);

					(
						KeccakfState(must_cast(absorbed_pre_hash_state)),
						KeccakfState(must_cast(row.post_hash_state)),
					)
				})
				.collect_vec();

			let mut zeros_keccakf = KeccakfState::default();
			tiny_keccak::keccakf(&mut zeros_keccakf.0);
			input_output
				.resize_with(1 << n_vars_total, || (KeccakfState::default(), zeros_keccakf));

			pack_witness(
				builder_prover,
				&input_output,
				&keccakf_pull_body,
				F64::TOWER_LEVEL,
				|(input, output)| chain!(&input.0, &output.0).copied(),
			);

			builder_prover
				.receive(keccakf_channel, count_total, keccakf_pull_body)
				.unwrap();

			let count_extra = self.extra_traces.len();
			let n_vars_extra = log2_ceil_usize(count_extra);

			let keccakf_push_body_extra = pack_oracles(
				builder_prover,
				"keccakf_push_body_extra",
				n_vars_extra,
				F8::TOWER_LEVEL,
				chain!(
					&padded_absorbed_extra,
					&extra_trace_oracles.pre_hash_state[SINGLE_PREIMAGE_ABSORB_BYTE_SIZE..],
					&extra_trace_oracles.post_hash_state
				)
				.copied(),
			)
			.unwrap();

			pack_witness(
				builder_prover,
				&self.extra_traces,
				&keccakf_push_body_extra,
				F8::TOWER_LEVEL,
				|row| {
					chain!(
						&row.padded_absorbed,
						&row.pre_hash_state[SINGLE_PREIMAGE_ABSORB_BYTE_SIZE..],
						&row.post_hash_state
					)
					.copied()
				},
			);

			builder_prover
				.send(keccakf_channel, count_extra, keccakf_push_body_extra)
				.unwrap();
		} else {
			// No extra traces case

			let count_base = self.base_traces.len();
			let n_vars_base = log2_ceil_usize(count_base);
			let mut states = self
				.base_traces
				.clone()
				.into_iter()
				.map(|row| {
					let mut absorbed_pre_hash_state = row.pre_hash_state;
					absorbed_pre_hash_state[..SINGLE_PREIMAGE_ABSORB_BYTE_SIZE]
						.copy_from_slice(&row.padded_absorbed);
					KeccakfState(must_cast(absorbed_pre_hash_state))
				})
				.collect_vec();

			states.resize_with(1 << n_vars_base, KeccakfState::default);

			let keccakf_oracles = keccakf(builder_prover, &Some(states), n_vars_base).unwrap();

			let keccakf_pull_body = pack_oracles(
				builder_prover,
				"keccakf_pull_body",
				n_vars_base,
				F64::TOWER_LEVEL,
				chain!(&keccakf_oracles.input, &keccakf_oracles.output).copied(),
			)
			.unwrap();

			let mut input_output = self
				.base_traces
				.clone()
				.into_iter()
				.map(|row| {
					let mut absorbed_pre_hash_state = row.pre_hash_state;
					absorbed_pre_hash_state[..SINGLE_PREIMAGE_ABSORB_BYTE_SIZE]
						.copy_from_slice(&row.padded_absorbed);

					(
						KeccakfState(must_cast(absorbed_pre_hash_state)),
						KeccakfState(must_cast(row.post_hash_state)),
					)
				})
				.collect_vec();

			let mut zeros_keccakf = KeccakfState::default();
			tiny_keccak::keccakf(&mut zeros_keccakf.0);
			input_output.resize_with(1 << n_vars_base, || (KeccakfState::default(), zeros_keccakf));

			pack_witness(
				builder_prover,
				&input_output,
				&keccakf_pull_body,
				F64::TOWER_LEVEL,
				|(input, output)| chain!(&input.0, &output.0).copied(),
			);

			// ... is balanced by this receiving
			builder_prover
				.receive(keccakf_channel, count_base, keccakf_pull_body)
				.unwrap();
		}

		builder_prover.pop_namespace();
	}

	////////////////////////////////////////////////////////////////////////////////////
	////// VERIFIER
	////////////////////////////////////////////////////////////////////////////////////

	// Verifier's API is identical to Prover's one, with the only difference - no witness population happens

	pub fn memory_lookup_verifier(
		&mut self,
		memory_verifier: &mut MemoryGadget,
		builder_verifier: &mut ConstraintSystemBuilder,
	) -> (BaseTraceOracles, Option<ExtraTraceOracles>) {
		builder_verifier.push_namespace("memory_lookup_verifier");

		fn inner(
			name: impl ToString,
			memory_verifier: &mut MemoryGadget,
			builder_verifier: &mut ConstraintSystemBuilder,
			traces: &Vec<TraceRow>,
		) -> (
			[OracleId; KECCAK_STATE_BYTE_SIZE],
			OracleId,
			OracleId,
			OracleId,
			[OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE],
			[OracleId; KECCAK_STATE_BYTE_SIZE],
		) {
			builder_verifier.push_namespace(name);

			let count = traces.len();
			let n_vars = log2_ceil_usize(count);

			let preimage_offset =
				builder_verifier.add_committed("preimage_offset", n_vars, F32::TOWER_LEVEL);
			let single_preimage_absorb = builder_verifier
				.add_committed_multiple::<SINGLE_PREIMAGE_ABSORB_BYTE_SIZE>(
					"single_preimage_absorb",
					n_vars,
					F8::TOWER_LEVEL,
				);
			single_preimage_absorb
				.iter()
				.enumerate()
				.map(|(offset, &byte_value)| {
					memory_verifier.read_byte_oracle(
						builder_verifier,
						"single_preimage_absorb_lookup",
						preimage_offset,
						byte_value,
						count,
						offset,
					)
				})
				.collect::<Result<Vec<_>, _>>()
				.unwrap();

			let pre_hash_state = builder_verifier.add_committed_multiple::<KECCAK_STATE_BYTE_SIZE>(
				"pre_hash_state",
				n_vars,
				F8::TOWER_LEVEL,
			);
			let post_hash_state = builder_verifier
				.add_committed_multiple::<KECCAK_STATE_BYTE_SIZE>(
					"post_hash_state",
					n_vars,
					F8::TOWER_LEVEL,
				);

			let hash_offset =
				builder_verifier.add_committed("hash_offset", n_vars, F32::TOWER_LEVEL);
			let preimage_length =
				builder_verifier.add_committed("preimage_length", n_vars, F32::TOWER_LEVEL);

			builder_verifier.pop_namespace();

			(
				pre_hash_state,
				preimage_offset,
				preimage_length,
				hash_offset,
				single_preimage_absorb,
				post_hash_state,
			)
		}

		let (
			pre_hash_state,
			preimage_offset,
			preimage_length,
			hash_offset,
			single_preimage_absorb,
			post_hash_state,
		) = inner("base-traces", memory_verifier, builder_verifier, &self.base_traces);

		post_hash_state[..HASH_SIZE]
			.iter()
			.enumerate()
			.map(|(offset, &byte_value)| {
				memory_verifier.read_byte_oracle(
					builder_verifier,
					"hash_squeeze_rom_read_lookup",
					hash_offset,
					byte_value,
					self.base_traces.len(),
					offset,
				)
			})
			.collect::<Result<Vec<_>, _>>()
			.unwrap();

		let extra_trace_oracles = if self.extra_traces.len() > 0 {
			let (
				pre_hash_state,
				preimage_offset,
				preimage_length,
				hash_offset,
				single_preimage_absorb,
				post_hash_state,
			) = inner("extra-traces", memory_verifier, builder_verifier, &self.extra_traces);
			Some(ExtraTraceOracles {
				pre_hash_state,
				preimage_offset,
				preimage_length,
				hash_offset,
				single_preimage_absorb,
				post_hash_state,
			})
		} else {
			None
		};

		memory_verifier.run_lookup(builder_verifier).unwrap();

		builder_verifier.pop_namespace();

		(
			BaseTraceOracles {
				pre_hash_state,
				preimage_offset,
				preimage_length,
				hash_offset,
				single_preimage_absorb,
				post_hash_state,
			},
			extra_trace_oracles,
		)
	}

	pub fn trace_slice_correlation_verifier(
		&mut self,
		builder_verifier: &mut ConstraintSystemBuilder,
		base_trace_oracles: &BaseTraceOracles,
		extra_trace_oracles: Option<&ExtraTraceOracles>,
	) {
		builder_verifier.push_namespace("trace_slice_correlation_verifier");

		let count = self.base_traces.len();
		let n_vars = log2_ceil_usize(count);

		let packed_pre_hash_state = pack_oracles(
			builder_verifier,
			"packed_pre_hash_state_verifier",
			n_vars,
			F8::TOWER_LEVEL,
			base_trace_oracles.pre_hash_state,
		)
		.unwrap();

		let memory_slice_info_channel = builder_verifier.add_channel();

		builder_verifier
			.receive(
				memory_slice_info_channel,
				count,
				packed_pre_hash_state.into_iter().chain([
					base_trace_oracles.preimage_offset,
					base_trace_oracles.preimage_length,
					base_trace_oracles.hash_offset,
				]),
			)
			.unwrap();

		let preimage_offset =
			builder_verifier.add_committed("preimage_offset_verifier", n_vars, F32::TOWER_LEVEL);
		let preimage_length =
			builder_verifier.add_committed("preimage_length_verifier", n_vars, F32::TOWER_LEVEL);
		let hash_offset =
			builder_verifier.add_committed("hash_offset_verifier", n_vars, F32::TOWER_LEVEL);
		let zero_column = builder_verifier
			.add_transparent("zero_column_verifier", Constant::new(n_vars, F::ZERO))
			.unwrap();

		let per_lincom = 1 << (F::TOWER_LEVEL - F8::TOWER_LEVEL);
		let mut flush_oracles = vec![zero_column; KECCAK_STATE_BYTE_SIZE.div_ceil(per_lincom)];
		flush_oracles.extend([preimage_offset, preimage_length, hash_offset]);

		builder_verifier
			.send(memory_slice_info_channel, count, flush_oracles)
			.unwrap();

		if self.extra_traces.len() > 0 {
			let extra_trace_oracles = extra_trace_oracles.unwrap();

			let count_extra = self.extra_traces.len();
			let n_vars_extra = log2_ceil_usize(count_extra);
			let hash_r_mult_stride =
				F32::MULTIPLICATIVE_GENERATOR.pow(SINGLE_PREIMAGE_ABSORB_BYTE_SIZE as u64);
			let hash_r_mult_stride_inverse =
				hash_r_mult_stride.invert().expect("nonzero by definition");

			let next_preimage_offset_extra = builder_verifier
				.add_linear_combination(
					"next_preimage_offset_verifier",
					n_vars_extra,
					[(extra_trace_oracles.preimage_offset, hash_r_mult_stride.into())],
				)
				.unwrap();

			let next_preimage_length_extra = builder_verifier
				.add_linear_combination(
					"next_remaining_bytes_verifier",
					n_vars_extra,
					[(extra_trace_oracles.preimage_length, hash_r_mult_stride_inverse.into())],
				)
				.unwrap();

			let packed_pre_hash_state_extra = pack_oracles(
				builder_verifier,
				"packed_pre_hash_state_extra_verifier",
				n_vars_extra,
				F8::TOWER_LEVEL,
				extra_trace_oracles.pre_hash_state,
			)
			.unwrap();

			let packed_post_hash_state_extra = pack_oracles(
				builder_verifier,
				"packed_post_hash_state_extra_verifier",
				n_vars_extra,
				F8::TOWER_LEVEL,
				extra_trace_oracles.post_hash_state,
			)
			.unwrap();

			builder_verifier
				.receive(
					memory_slice_info_channel,
					count_extra,
					packed_pre_hash_state_extra.into_iter().chain([
						extra_trace_oracles.preimage_offset,
						extra_trace_oracles.preimage_length,
						extra_trace_oracles.hash_offset,
					]),
				)
				.unwrap();

			builder_verifier
				.send(
					memory_slice_info_channel,
					count_extra,
					packed_post_hash_state_extra.into_iter().chain([
						next_preimage_offset_extra,
						next_preimage_length_extra,
						extra_trace_oracles.hash_offset,
					]),
				)
				.unwrap();
		}

		builder_verifier.pop_namespace();
	}

	pub fn padding_consistency_verifier(
		&mut self,
		builder_verifier: &mut ConstraintSystemBuilder,
		base_trace_oracles: &BaseTraceOracles,
		extra_trace_oracles: Option<&ExtraTraceOracles>,
	) -> (
		[OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE],
		Vec<OracleId>,
		[OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE],
		Option<[OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE]>,
	) {
		builder_verifier.push_namespace("padding_consistency_verifier");

		let count = self.base_traces.len();
		let n_vars = log2_ceil_usize(count);

		let selector = builder_verifier.add_committed_multiple::<SINGLE_PREIMAGE_ABSORB_BYTE_SIZE>(
			"selector_verifier",
			n_vars,
			F1::TOWER_LEVEL,
		);
		let packed_selector_u = pack_oracles(
			builder_verifier,
			"packed_selector_u_verifier",
			n_vars,
			F1::TOWER_LEVEL,
			selector,
		)
		.unwrap();

		let padded_absorbed = builder_verifier
			.add_committed_multiple::<SINGLE_PREIMAGE_ABSORB_BYTE_SIZE>(
				"padded_absorbed_verifier",
				n_vars,
				F8::TOWER_LEVEL,
			);

		let padding_values = builder_verifier
			.add_committed_multiple::<SINGLE_PREIMAGE_ABSORB_BYTE_SIZE>(
				"padding_values_verifier",
				n_vars,
				F8::TOWER_LEVEL,
			);

		let padding_consistency = arith_expr!(
			[padded, pre_hash_state, selector, padding_value, rom_read] =
				padded + pre_hash_state + selector * rom_read + (1 - selector) * padding_value
		);

		izip!(
			&padded_absorbed,
			&base_trace_oracles.pre_hash_state,
			&selector,
			&padding_values,
			&base_trace_oracles.single_preimage_absorb
		)
		.enumerate()
		.for_each(
			|(i, (&padded, &pre_hash_state, &selector, &padding_value, &absorbed_byte))| {
				builder_verifier.assert_zero(
					format!("padding_consistency_verifier_{}", i),
					[
						padded,
						pre_hash_state,
						selector,
						padding_value,
						absorbed_byte,
					],
					padding_consistency.clone().convert_field(),
				)
			},
		);

		let padded_absorbed_extra = if self.extra_traces.len() > 0 {
			let extra_trace_oracles = extra_trace_oracles.unwrap();

			let count_extra = self.extra_traces.len();
			let n_vars_extra = log2_ceil_usize(count_extra);
			let padded_absorbed_extra: [OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE] =
				array::from_fn(|i| {
					builder_verifier
						.add_linear_combination(
							format!("padded_absorbed_extra{}", i),
							n_vars_extra,
							[
								(extra_trace_oracles.single_preimage_absorb[i], F::ONE),
								(extra_trace_oracles.pre_hash_state[i], F::ONE),
							],
						)
						.expect(
							"block rom read and pre hash state oracles newly added; \
                     all of them have ceil(log2(count)) variables.",
						)
				});
			Some(padded_absorbed_extra)
		} else {
			None
		};

		builder_verifier.pop_namespace();

		(padding_values, packed_selector_u, padded_absorbed, padded_absorbed_extra)
	}

	pub fn padding_lookup_verifier(
		&mut self,
		builder_verifier: &mut ConstraintSystemBuilder,
		padding_values: [OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE],
		packed_selector_u: Vec<OracleId>,
		preimage_length: OracleId,
	) {
		builder_verifier.push_namespace("padding_lookup_verifier");

		let count = self.base_traces.len();
		let n_vars = log2_ceil_usize(count);
		let lookup_n_vars = log2_ceil_usize(SINGLE_PREIMAGE_ABSORB_BYTE_SIZE);

		let remaining_bytes_t = builder_verifier.add_committed(
			"remaining_bytes_t_verifier",
			lookup_n_vars,
			F32::TOWER_LEVEL,
		);

		let packed_padding_values_u = pack_oracles(
			builder_verifier,
			"packed_padding_values_u_verifier",
			n_vars,
			F8::TOWER_LEVEL,
			padding_values,
		)
		.unwrap();

		let selector_t = builder_verifier
			.add_committed_multiple::<SINGLE_PREIMAGE_ABSORB_BYTE_SIZE>(
				"selector_t",
				lookup_n_vars,
				F1::TOWER_LEVEL,
			);
		let packed_selector_t = pack_oracles(
			builder_verifier,
			"packed_selector_t_verifier",
			lookup_n_vars,
			F1::TOWER_LEVEL,
			selector_t,
		)
		.unwrap();

		let padding_values_t = builder_verifier
			.add_committed_multiple::<SINGLE_PREIMAGE_ABSORB_BYTE_SIZE>(
				"padding_values_t_verifier",
				lookup_n_vars,
				F8::TOWER_LEVEL,
			);

		let packed_padding_values_t = pack_oracles(
			builder_verifier,
			"packed_padding_values_t_verifier",
			lookup_n_vars,
			F8::TOWER_LEVEL,
			padding_values_t,
		)
		.unwrap();

		let lookup_u =
			chain!(packed_selector_u, packed_padding_values_u, [preimage_length]).collect_vec();

		let lookup_t =
			chain!(packed_selector_t, packed_padding_values_t, [remaining_bytes_t]).collect_vec();

		let padding_lasso_channel = builder_verifier.add_channel();
		let u_to_t_mapping = Vec::new();

		lasso::lasso::<F32>(
			builder_verifier,
			"padding_lasso_verifier",
			&[count],
			&[u_to_t_mapping],
			&[lookup_u],
			&lookup_t,
			padding_lasso_channel,
		)
		.unwrap();

		builder_verifier.pop_namespace();
	}

	pub fn keccak_state_transition_verifier(
		&mut self,
		builder_verifier: &mut ConstraintSystemBuilder,
		padded_absorbed: [OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE],
		padded_absorbed_extra: Option<[OracleId; SINGLE_PREIMAGE_ABSORB_BYTE_SIZE]>,
		base_trace_oracles: &BaseTraceOracles,
		extra_trace_oracles: Option<&ExtraTraceOracles>,
	) {
		builder_verifier.push_namespace("keccak_state_transition_verifier");

		let count_base = self.base_traces.len();
		let n_vars_base = log2_ceil_usize(count_base);

		let state_transition_channel = builder_verifier.add_channel();

		let keccakf_push_body = pack_oracles(
			builder_verifier,
			"keccakf_push_body",
			n_vars_base,
			F8::TOWER_LEVEL,
			chain!(
				&padded_absorbed,
				&base_trace_oracles.pre_hash_state[SINGLE_PREIMAGE_ABSORB_BYTE_SIZE..],
				&base_trace_oracles.post_hash_state
			)
			.copied(),
		)
		.unwrap();

		builder_verifier
			.send(state_transition_channel, count_base, keccakf_push_body)
			.unwrap();

		if self.extra_traces.len() > 0 {
			let padded_absorbed_extra = padded_absorbed_extra.unwrap();
			let extra_trace_oracles = extra_trace_oracles.unwrap();

			let count_total = self.base_traces.len() + self.extra_traces.len();
			let n_vars_total = log2_ceil_usize(count_total);

			let keccakf_oracles =
				keccakf(builder_verifier, &None::<&[KeccakfState]>, n_vars_total).unwrap();

			let keccakf_pull_body = pack_oracles(
				builder_verifier,
				"keccakf_pull_body_extra_traces",
				n_vars_total,
				F64::TOWER_LEVEL,
				chain!(&keccakf_oracles.input, &keccakf_oracles.output).copied(),
			)
			.unwrap();

			builder_verifier
				.receive(state_transition_channel, count_total, keccakf_pull_body)
				.unwrap();

			let count_extra = self.extra_traces.len();
			let n_vars_extra = log2_ceil_usize(count_extra);

			let keccakf_push_body_extra = pack_oracles(
				builder_verifier,
				"keccakf_push_body_extra",
				n_vars_extra,
				F8::TOWER_LEVEL,
				chain!(
					&padded_absorbed_extra,
					&extra_trace_oracles.pre_hash_state[SINGLE_PREIMAGE_ABSORB_BYTE_SIZE..],
					&extra_trace_oracles.post_hash_state
				)
				.copied(),
			)
			.unwrap();

			builder_verifier
				.send(state_transition_channel, count_extra, keccakf_push_body_extra)
				.unwrap();
		} else {
			let count_base = self.base_traces.len();
			let n_vars_base = log2_ceil_usize(count_base);

			let keccakf_oracles =
				keccakf(builder_verifier, &None::<&[KeccakfState]>, n_vars_base).unwrap();

			let keccakf_pull_body = pack_oracles(
				builder_verifier,
				"keccakf_pull_body",
				n_vars_base,
				F64::TOWER_LEVEL,
				chain!(&keccakf_oracles.input, &keccakf_oracles.output).copied(),
			)
			.unwrap();

			// ... is balanced by this receiving
			builder_verifier
				.receive(state_transition_channel, count_base, keccakf_pull_body)
				.unwrap();
		}

		builder_verifier.pop_namespace();
	}
}

// Utilities
pub fn transpose_rows<Field, Row, Return>(
	builder: &mut ConstraintSystemBuilder,
	rows_witness: &[Row],
	column_oracle: OracleId,
	getter: impl Fn(&Row) -> Option<Return> + Sync,
) -> anyhow::Result<()>
where
	U: UnderlierType + Pod + PackScalar<F> + PackScalar<Field>,
	F: ExtensionField<Field>,
	Field: TowerField,
	Row: Sync,
	Return: Pod + Send,
{
	let Some(witness) = builder.witness() else {
		todo!();
	};

	let mut column = witness.new_column::<Field>(column_oracle);
	let column_pod = column.as_mut_slice::<Return>();

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

pub fn transpose_scalar_matrix<'a, Field, Row, ReturnIter>(
	builder: &mut ConstraintSystemBuilder,
	rows_witness: &'a [Row],
	columns: impl IntoIterator<Item = OracleId>,
	getter: impl Fn(&'a Row) -> ReturnIter + Sync,
) -> anyhow::Result<()>
where
	U: UnderlierType + PackScalar<F> + PackScalar<Field>,
	F: ExtensionField<Field>,
	Field: TowerField,
	Row: Sync,
	ReturnIter: Iterator<Item = Field>,
{
	let Some(witness) = builder.witness() else {
		todo!();
	};

	let width = PackedType::<U, Field>::WIDTH;

	for (column_index, column_oracle) in columns.into_iter().enumerate() {
		let mut column = witness.new_column::<Field>(column_oracle);
		column.packed().par_iter_mut().enumerate().try_for_each(
			|(i, packed)| -> anyhow::Result<()> {
				for j in 0..width {
					let row_index = i * width + j;
					if let Some(row) = rows_witness.get(row_index) {
						packed.set(
							j,
							getter(row).nth(column_index).ok_or_else(|| {
								anyhow!("can't sample column {} at row {}", column_index, row_index)
							})?,
						)
					}
				}

				Ok(())
			},
		)?;
	}

	Ok(())
}

pub fn pack_oracles(
	builder: &mut ConstraintSystemBuilder,
	group_name: &str,
	n_vars: usize,
	packed_tower_level: usize,
	oracles: impl IntoIterator<Item = OracleId, IntoIter: Clone>,
) -> anyhow::Result<Vec<OracleId>> {
	assert!(packed_tower_level <= F::TOWER_LEVEL);

	let iter = oracles.into_iter();
	let per_lincom = 1 << (F::TOWER_LEVEL - packed_tower_level);
	let lincoms = iter.clone().count().div_ceil(per_lincom);

	(0..lincoms)
		.map(|i| {
			Ok(builder.add_linear_combination(
				format!("{}_{}", group_name, i),
				n_vars,
				iter.clone()
					.skip(per_lincom * i)
					.take(per_lincom)
					.enumerate()
					.map(|(j, column)| {
						let basis = <F as TowerField>::basis(packed_tower_level, j)
							.expect("per_lincom is chosen to never overflow B128");

						(column, basis)
					}),
			)?)
		})
		.collect()
}

pub fn pack_witness<'a, Row, ReturnIter>(
	builder: &mut ConstraintSystemBuilder,
	rows_witness: &'a [Row],
	lincom_oracles: &[OracleId],
	packed_tower_level: usize,
	getter: impl Fn(&'a Row) -> ReturnIter + Sync,
) where
	Row: Sync,
	ReturnIter: Iterator<Item: Pod + Send> + Clone,
	u128: From<ReturnIter::Item>,
{
	assert!(packed_tower_level <= F::TOWER_LEVEL);

	let Some(witness) = builder.witness() else {
		todo!()
	};

	let per_lincom = 1 << (F::TOWER_LEVEL - packed_tower_level);

	for (i, &lincom_oracle) in lincom_oracles.iter().enumerate() {
		let mut column = witness.new_column::<F>(lincom_oracle);
		let column_u128 = column.as_mut_slice::<u128>();

		column_u128
			.par_iter_mut()
			.zip(rows_witness)
			.for_each(|(dest, row)| {
				*dest = getter(row)
					.skip(per_lincom * i)
					.take(per_lincom)
					.enumerate()
					.fold(0u128, |acc, (j, column_value)| {
						acc | (u128::from(column_value) << (j << packed_tower_level))
					});
			});
	}
}

pub fn selector_fn(len: usize) -> impl Iterator<Item = F1> + Clone {
	assert!(len < SINGLE_PREIMAGE_ABSORB_BYTE_SIZE, "trying to pad in non-base case");
	chain!(repeat_n(F1::ONE, len), repeat_n(F1::ZERO, SINGLE_PREIMAGE_ABSORB_BYTE_SIZE - len))
}

pub fn padding_values_fn(len: usize) -> impl Iterator<Item = F8> + Clone {
	assert!(len < SINGLE_PREIMAGE_ABSORB_BYTE_SIZE, "trying to pad in non-base case");
	(0..SINGLE_PREIMAGE_ABSORB_BYTE_SIZE).map(move |index| {
		let mut padding_byte = 0u8;

		if index == len {
			padding_byte |= 0x01;
		}

		if index == SINGLE_PREIMAGE_ABSORB_BYTE_SIZE - 1 {
			padding_byte |= 0x80;
		}

		F8::new(padding_byte)
	})
}
