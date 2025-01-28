// Copyright 2024-2025 Irreducible Inc.

use binius_maybe_rayon::iter::IndexedParallelIterator;
use bytes::{Buf, BufMut};

use super::errors::Error;
use crate::transcript::{TranscriptReader, TranscriptWriter};

/// A Merkle tree commitment.
///
/// This struct includes the depth of the tree to guard against attacks that exploit the
/// indistinguishability of leaf digests from inner node digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment<Digest> {
	/// The root digest of the Merkle tree.
	pub root: Digest,
	/// The depth of the Merkle tree.
	pub depth: usize,
}

/// A Merkle tree scheme.
pub trait MerkleTreeScheme<T>: Sync {
	type Digest: Clone + PartialEq + Eq;

	/// Returns the optimal layer that the verifier should verify only once.
	fn optimal_verify_layer(&self, n_queries: usize, tree_depth: usize) -> usize;

	/// Returns the total byte-size of a proof for multiple opening queries.
	///
	/// ## Arguments
	///
	/// * `len` - the length of the committed vector
	/// * `n_queries` - the number of opening queries
	fn proof_size(&self, len: usize, n_queries: usize, layer_depth: usize) -> Result<usize, Error>;

	/// Verify the opening of the full vector.
	fn verify_vector(
		&self,
		root: &Self::Digest,
		data: &[T],
		batch_size: usize,
	) -> Result<(), Error>;

	/// Verify a given layer of the Merkle tree.
	///
	/// When a protocol requires verification of many openings at independent and randomly sampled
	/// indices, it is more efficient for the verifier to verifier an internal layer once, then
	/// verify all openings with respect to that layer.
	fn verify_layer(
		&self,
		root: &Self::Digest,
		layer_depth: usize,
		layer_digests: &[Self::Digest],
	) -> Result<(), Error>;

	/// Verify an opening proof for an entry in a committed vector at the given index.
	fn verify_opening<B: Buf>(
		&self,
		index: usize,
		values: &[T],
		layer_depth: usize,
		tree_depth: usize,
		layer_digests: &[Self::Digest],
		proof: &mut TranscriptReader<B>,
	) -> Result<(), Error>;
}

/// A Merkle tree prover for a particular scheme.
///
/// This is separate from [`MerkleTreeScheme`] so that it may be implemented using a
/// hardware-accelerated backend.
pub trait MerkleTreeProver<T>: Sync {
	type Scheme: MerkleTreeScheme<T>;
	/// Data generated during commitment required to generate opening proofs.
	type Committed;

	/// Returns the Merkle tree scheme used by the prover.
	fn scheme(&self) -> &Self::Scheme;

	/// Commit a vector of values.
	#[allow(clippy::type_complexity)]
	fn commit(
		&self,
		data: &[T],
		batch_size: usize,
	) -> Result<(Commitment<<Self::Scheme as MerkleTreeScheme<T>>::Digest>, Self::Committed), Error>;

	/// Commit interleaved elements from iterator by val
	#[allow(clippy::type_complexity)]
	fn commit_iterated<ParIter>(
		&self,
		iterated_chunks: ParIter,
		log_len: usize,
	) -> Result<(Commitment<<Self::Scheme as MerkleTreeScheme<T>>::Digest>, Self::Committed), Error>
	where
		ParIter: IndexedParallelIterator<Item: IntoIterator<Item = T>>;

	/// Returns the internal digest layer at the given depth.
	fn layer<'a>(
		&self,
		committed: &'a Self::Committed,
		layer_depth: usize,
	) -> Result<&'a [<Self::Scheme as MerkleTreeScheme<T>>::Digest], Error>;

	/// Generate an opening proof for an entry in a committed vector at the given index.
	///
	/// ## Arguments
	///
	/// * `committed` - helper data generated during commitment
	/// * `layer_depth` - depth of the layer to prove inclusion in
	/// * `index` - the entry index
	fn prove_opening<B: BufMut>(
		&self,
		committed: &Self::Committed,
		layer_depth: usize,
		index: usize,
		proof: &mut TranscriptWriter<B>,
	) -> Result<(), Error>;
}
