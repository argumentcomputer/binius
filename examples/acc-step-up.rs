use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::{constraint_system::validate::validate_witness, transparent::step_up::StepUp};
use binius_field::BinaryField8b;

type F8 = BinaryField8b;

const LOG_SIZE: usize = 8;

// StepUp expects all bytes to be unset before particular index specified as input (opposite to StepDown)
fn main() {
	let allocator = bumpalo::Bump::new();
	let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);

	let index = 10;

	let step_up = StepUp::new(LOG_SIZE, index).unwrap();
	let transparent = builder.add_transparent("step_up", step_up).unwrap();

	if let Some(witness) = builder.witness() {
		let mut transparent_witness = witness.new_column::<F8>(transparent);
		let values = transparent_witness.as_mut_slice::<u8>();

		values[index..].fill(0x01);
	}

	let witness = builder.take_witness().unwrap();
	let constraints_system = builder.build().unwrap();

	validate_witness(&constraints_system, &[], &witness).unwrap();
}
