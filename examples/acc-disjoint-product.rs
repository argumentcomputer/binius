use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::{
	constraint_system::validate::validate_witness,
	transparent::{constant::Constant, disjoint_product::DisjointProduct, powers::Powers},
};
use binius_field::{
	arch::OptimalUnderlier, BinaryField, BinaryField128b, BinaryField8b, PackedField,
};

type U = OptimalUnderlier;
type F128 = BinaryField128b;
type F8 = BinaryField8b;

const LOG_SIZE: usize = 4;

// FIXME: Following gadgets are unconstrained. Only for demonstrative purpose, don't use in production

// DisjointProduct can be used for creating some more elaborated regularities over public data.
// In the following example we have a Transparent column with DisjointProduct instantiated over Powers
// and Constant. In this regularity, the DisjointProduct would be represented as a following expression:
//
// [ c * F8(x)^0, c * F8(x)^1, c * F8(x)^2, ... c * F8(x)^(2^LOG_SIZE) ],
//
// where
// 'x' is a multiplicative generator - a public value that exists for every BinaryField,
// 'c' is some (F8) constant.
//
// Also note, that DisjointProduct makes eventual Transparent column to have height (n_vars) which is sum
// of heights (n_vars) of Powers and Constant, so actual data could be repeated multiple times
fn main() {
	let allocator = bumpalo::Bump::new();
	let mut builder = ConstraintSystemBuilder::<U, F128>::new_with_witness(&allocator);

	let generator = F8::MULTIPLICATIVE_GENERATOR;
	let powers = Powers::new(LOG_SIZE, generator.into());

	let constant_value = F8::new(0xf0);
	let constant = Constant::new(LOG_SIZE, constant_value);

	let disjoint_product = DisjointProduct(powers, constant);
	let disjoint_product_id = builder
		.add_transparent("disjoint_product", disjoint_product)
		.unwrap();

	if let Some(witness) = builder.witness() {
		let mut disjoint_product_witness = witness.new_column::<F8>(disjoint_product_id);

		let values = disjoint_product_witness.as_mut_slice::<F8>();

		let mut exponent = 0u64;
		for val in values.iter_mut() {
			if exponent == 2u64.pow(LOG_SIZE as u32) {
				exponent = 0;
			}
			*val = generator.pow(exponent) * constant_value;
			exponent += 1;
		}
	}

	let witness = builder.take_witness().unwrap();
	let constraints_system = builder.build().unwrap();

	validate_witness(&constraints_system, &[], &witness).unwrap();
}
