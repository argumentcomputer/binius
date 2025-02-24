use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::{
	constraint_system::validate::validate_witness, transparent::select_row::SelectRow,
};
use binius_field::BinaryField8b;

type F8 = BinaryField8b;

const LOG_SIZE: usize = 8;

// SelectRow expects exactly one witness value at particular index to be set.
fn main() {
	let allocator = bumpalo::Bump::new();
	let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);

	let index = 58;
	assert!(index < 1 << LOG_SIZE);

	let select_row = SelectRow::new(LOG_SIZE, index).unwrap();
	let transparent = builder.add_transparent("select_row", select_row).unwrap();

	if let Some(witness) = builder.witness() {
		let mut transparent_witness = witness.new_column::<F8>(transparent);
		let values = transparent_witness.as_mut_slice::<u8>();

		values[index] = 0x01;
	}

	let witness = builder.take_witness().unwrap();
	let constraints_system = builder.build().unwrap();

	validate_witness(&constraints_system, &[], &witness).unwrap();
}
