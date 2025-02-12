use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::constraint_system::validate::validate_witness;
use binius_field::{
	arch::OptimalUnderlier, BinaryField, BinaryField128b, BinaryField16b, BinaryField32b,
	PackedField,
};

type U = OptimalUnderlier;
type F128 = BinaryField128b;
type F32 = BinaryField32b;
type F16 = BinaryField16b;

const LOG_SIZE: usize = 3;

// FIXME: Following gadgets are unconstrained. Only for demonstrative purpose, don't use in production

// Values for the Transparent columns are known to verifier, so they can be used for storing non-private data
// (like constants for example). The following gadget demonstrates how to use Powers abstraction to build a
// Transparent column that keeps following values (we write them during witness population):
//
// [ F32(x)^0, F32(x)^1 , F32(x)^2, ... F32(x)^(2^LOG_SIZE) ],

// where 'x' is a multiplicative generator - a public value that exists for every BinaryField
//
fn powers_gadget_f32(builder: &mut ConstraintSystemBuilder<U, F128>) {
	let generator = F32::MULTIPLICATIVE_GENERATOR;
	let powers = binius_core::transparent::powers::Powers::new(LOG_SIZE, generator.into());
	let transparent = builder
		.add_transparent("Powers of F32 gen", powers)
		.unwrap();

	if let Some(witness) = builder.witness() {
		let mut transparent_witness = witness.new_column::<F32>(transparent);
		let transparent_values = transparent_witness.as_mut_slice::<F32>();
		for (exp, val) in transparent_values.iter_mut().enumerate() {
			*val = generator.pow(exp as u64);
		}
	}
}

// Only Field is being changed
fn powers_gadget_f16(builder: &mut ConstraintSystemBuilder<U, F128>) {
	let generator = F16::MULTIPLICATIVE_GENERATOR;
	let powers = binius_core::transparent::powers::Powers::new(LOG_SIZE, generator.into());
	let transparent = builder
		.add_transparent("Powers of F16 gen", powers)
		.unwrap();

	if let Some(witness) = builder.witness() {
		let mut transparent_witness = witness.new_column::<F16>(transparent);
		let transparent_values = transparent_witness.as_mut_slice::<F16>();
		for (exp, val) in transparent_values.iter_mut().enumerate() {
			*val = generator.pow(exp as u64);
		}
	}
}

fn main() {
	let allocator = bumpalo::Bump::new();
	let mut builder = ConstraintSystemBuilder::<U, F128>::new_with_witness(&allocator);

	powers_gadget_f16(&mut builder);
	powers_gadget_f32(&mut builder);

	let witness = builder.take_witness().unwrap();
	let constraints_system = builder.build().unwrap();

	validate_witness(&constraints_system, &[], &witness).unwrap();
}
