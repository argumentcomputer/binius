use binius_circuits::{builder::ConstraintSystemBuilder, unconstrained::unconstrained};
use binius_core::constraint_system::validate::validate_witness;
use binius_field::BinaryField8b;

type F8 = BinaryField8b;

const LOG_SIZE: usize = 4;

fn main() {
	let allocator = bumpalo::Bump::new();

	let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);

	let bytes = unconstrained::<F8>(&mut builder, "bytes", LOG_SIZE).unwrap();

	// Height of ZeroPadded column can't be smaller than input one.
	// If n_vars equals to LOG_SIZE, then no padding is required,
	// the ZeroPadded column will have same length as input one, so we use bigger number
	let n_vars = 5usize;
	let zeropadded = builder
		.add_zero_padded("zeropadded", bytes, n_vars)
		.unwrap();

	if let Some(witness) = builder.witness() {
		let input_values = witness.get::<F8>(bytes).unwrap().as_slice::<F8>();

		let mut zeropadded_witness = witness.new_column::<F8>(zeropadded);
		let zeropadded_values = zeropadded_witness.as_mut_slice::<F8>();

		// padding naturally happens in the end, so we just copy input data to ZeroPadded column
		zeropadded_values[..input_values.len()].copy_from_slice(input_values);

		assert_eq!(zeropadded_values.len(), 2usize.pow(n_vars as u32));
		assert!(n_vars >= LOG_SIZE);
		let zeroes_to_pad = 2usize.pow(n_vars as u32) - 2usize.pow(LOG_SIZE as u32);
		assert_eq!(zeroes_to_pad, zeropadded_values.len() - input_values.len());
	}

	let witness = builder.take_witness().unwrap();
	let cs = builder.build().unwrap();

	validate_witness(&cs, &[], &witness).unwrap();
}
