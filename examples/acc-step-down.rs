use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::{
	constraint_system::validate::validate_witness, transparent::step_down::StepDown,
};
use binius_field::{arch::OptimalUnderlier, BinaryField128b, BinaryField8b};

const LOG_SIZE: usize = 8;

type U = OptimalUnderlier;
type F128 = BinaryField128b;
type F8 = BinaryField8b;

// StepDown expects all bytes to be set before particular index specified as input
fn main() {
	let allocator = bumpalo::Bump::new();
	let mut builder = ConstraintSystemBuilder::<U, F128>::new_with_witness(&allocator);

	let index = 10;

	let step_down = StepDown::new(LOG_SIZE, index).unwrap();
	let transparent = builder.add_transparent("step_down", step_down).unwrap();

	if let Some(witness) = builder.witness() {
		let mut transparent_witness = witness.new_column::<F8>(transparent);
		let values = transparent_witness.as_mut_slice::<u8>();

		values[0..index].fill(0x01);
	}

	let witness = builder.take_witness().unwrap();
	let constraints_system = builder.build().unwrap();

	validate_witness(&constraints_system, &[], &witness).unwrap();
}
