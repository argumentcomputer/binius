use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::{
	constraint_system::validate::validate_witness, transparent::MultilinearExtensionTransparent,
};
use binius_field::{
	arch::OptimalUnderlier, as_packed_field::PackedType, underlier::WithUnderlier, BinaryField128b,
	BinaryField1b, PackedField,
};
use binius_utils::checked_arithmetics::log2_ceil_usize;
use bytemuck::{pod_collect_to_vec, Pod};

type U = OptimalUnderlier;
type F128 = BinaryField128b;
type F1 = BinaryField1b;

// From a perspective of circuits creation, MultilinearExtensionTransparent can be used naturally for decomposing integers to bits
fn decompose_transparent_u64(builder: &mut ConstraintSystemBuilder<U, F128>, x: u64) {
	builder.push_namespace("decompose_transparent_u64");

	let log_bits = log2_ceil_usize(64);

	let broadcasted = vec![x; 1 << (PackedType::<U, F1>::LOG_WIDTH.saturating_sub(log_bits))];

	let broadcasted_decomposed = into_packed_vec::<PackedType<U, F1>>(&broadcasted);

	let transparent_id = builder
		.add_transparent(
			"transparent",
			MultilinearExtensionTransparent::<_, PackedType<U, F128>, _>::from_values(
				broadcasted_decomposed,
			)
			.unwrap(),
		)
		.unwrap();

	if let Some(witness) = builder.witness() {
		let mut transparent_witness = witness.new_column::<F1>(transparent_id);
		let values = transparent_witness.as_mut_slice::<u64>();
		values.fill(x);
	}

	builder.pop_namespace();
}

fn decompose_transparent_u32(builder: &mut ConstraintSystemBuilder<U, F128>, x: u32) {
	builder.push_namespace("decompose_transparent_u32");

	let log_bits = log2_ceil_usize(32);

	let broadcasted = vec![x; 1 << (PackedType::<U, F1>::LOG_WIDTH.saturating_sub(log_bits))];

	let broadcasted_decomposed = into_packed_vec::<PackedType<U, F1>>(&broadcasted);

	let transparent_id = builder
		.add_transparent(
			"transparent",
			MultilinearExtensionTransparent::<_, PackedType<U, F128>, _>::from_values(
				broadcasted_decomposed,
			)
			.unwrap(),
		)
		.unwrap();

	if let Some(witness) = builder.witness() {
		let mut transparent_witness = witness.new_column::<F1>(transparent_id);
		let values = transparent_witness.as_mut_slice::<u32>();
		values.fill(x);
	}

	builder.pop_namespace();
}

fn main() {
	let allocator = bumpalo::Bump::new();
	let mut builder = ConstraintSystemBuilder::<U, F128>::new_with_witness(&allocator);

	decompose_transparent_u64(&mut builder, 0xff00ff00ff00ff00);
	decompose_transparent_u32(&mut builder, 0x00ff00ff);

	let witness = builder.take_witness().unwrap();
	let constraints_system = builder.build().unwrap();

	validate_witness(&constraints_system, &[], &witness).unwrap();
}

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
