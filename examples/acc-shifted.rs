use binius_circuits::{builder::ConstraintSystemBuilder, unconstrained::unconstrained};
use binius_core::{constraint_system::validate::validate_witness, oracle::ShiftVariant};
use binius_field::{arch::OptimalUnderlier, BinaryField128b, BinaryField1b};

type U = OptimalUnderlier;
type F128 = BinaryField128b;
type F1 = BinaryField1b;

// FIXME: Following gadgets are unconstrained. Only for demonstrative purpose, don't use in production

fn shift_right_gadget_u32(builder: &mut ConstraintSystemBuilder<U, F128>) {
	builder.push_namespace("u32_right_shift");

	// defined empirically and it is the same as 'block_bits' defined below
	let log_size = 5usize;

	// create column and write arbitrary bytes to it
	let input = unconstrained::<U, F128, F1>(builder, "input", log_size).unwrap();

	// we want to shift our u32 variable on 1 bit
	let shift_offset = 1;
	let shift_type = ShiftVariant::LogicalRight;

	// 'block_bits' defines type of integer to shift. Binius must understand how to treat actual data in memory behind the variable
	// So for u32 we have 32 bits of data, 32 = 2 ^ 5.
	let block_bits = 5;
	let shifted = builder
		.add_shifted("shifted", input, shift_offset, block_bits, shift_type)
		.unwrap();

	if let Some(witness) = builder.witness() {
		// get input values from the witness
		let input_values = witness.get::<F1>(input).unwrap().as_slice::<u32>(); // u32

		// write shifted input to the output
		let mut output_values = witness.new_column::<F1>(shifted);
		let output_values = output_values.as_mut_slice::<u32>(); // u32
		for i in 0..input_values.len() {
			output_values[i] = input_values[i] >> shift_offset; // shift right
		}
	}

	builder.pop_namespace();
}

fn shift_left_gadget_u8(builder: &mut ConstraintSystemBuilder<U, F128>) {
	builder.push_namespace("u8_left_shift");
	let log_size = 3usize;

	let input = unconstrained::<U, F128, F1>(builder, "input", log_size).unwrap();
	let shift_offset = 4;
	let shift_type = ShiftVariant::LogicalLeft;
	let block_bits = 3;
	let shifted = builder
		.add_shifted("shifted", input, shift_offset, block_bits, shift_type)
		.unwrap();

	if let Some(witness) = builder.witness() {
		let input_values = witness.get::<F1>(input).unwrap().as_slice::<u8>(); // u8
		let mut output_values = witness.new_column::<F1>(shifted);
		let output_values = output_values.as_mut_slice::<u8>(); // u8
		for i in 0..input_values.len() {
			output_values[i] = input_values[i] << shift_offset; // shift left
		}
	}

	builder.pop_namespace();
}

fn rotate_left_gadget_u16(builder: &mut ConstraintSystemBuilder<U, F128>) {
	builder.push_namespace("u16_rotate_right");
	let log_size = 4usize;

	let input = unconstrained::<U, F128, F1>(builder, "input", log_size).unwrap();
	let rotation_offset = 5;
	let rotation_type = ShiftVariant::CircularLeft;
	let block_bits = 4usize;
	let shifted = builder
		.add_shifted("shifted", input, rotation_offset, block_bits, rotation_type)
		.unwrap();

	if let Some(witness) = builder.witness() {
		// write rotated input to the output
		let input_values = witness.get::<F1>(input).unwrap().as_slice::<u16>(); // u16
		let mut output_values = witness.new_column::<F1>(shifted);
		let output_values = output_values.as_mut_slice::<u16>(); // u16
		for i in 0..input_values.len() {
			output_values[i] = input_values[i].rotate_left(rotation_offset as u32) // rotate left
		}
	}

	builder.pop_namespace();
}

fn rotate_right_gadget_u64(builder: &mut ConstraintSystemBuilder<U, F128>) {
	builder.push_namespace("u64_rotate_right");
	let log_size = 6usize;

	let input = unconstrained::<U, F128, F1>(builder, "input", log_size).unwrap();

	// Right rotation to X bits is achieved using 'ShiftVariant::CircularLeft' with the offset,
	// computed as size in bits of the variable type - X (e.g. if we want to right-rotate u64 to 8 bits,
	// we have to use CircularLeft with the offset = 64 - 8).
	let rotation_offset = 8;
	let rotation_type = ShiftVariant::CircularLeft;
	let block_bits = 6usize;
	let shifted = builder
		.add_shifted("shifted", input, 64 - rotation_offset, block_bits, rotation_type)
		.unwrap();

	if let Some(witness) = builder.witness() {
		// write rotated input to the output
		let input_values = witness.get::<F1>(input).unwrap().as_slice::<u64>(); // u64
		let mut output_values = witness.new_column::<F1>(shifted);
		let output_values = output_values.as_mut_slice::<u64>(); // u64
		for i in 0..input_values.len() {
			output_values[i] = input_values[i].rotate_right(rotation_offset as u32) // rotate right
		}
	}

	builder.pop_namespace();
}

fn main() {
	let allocator = bumpalo::Bump::new();

	let mut builder = ConstraintSystemBuilder::<U, F128>::new_with_witness(&allocator);

	shift_right_gadget_u32(&mut builder);
	shift_left_gadget_u8(&mut builder);
	rotate_left_gadget_u16(&mut builder);
	rotate_right_gadget_u64(&mut builder);

	let witness = builder.take_witness().unwrap();
	let cs = builder.build().unwrap();

	validate_witness(&cs, &[], &witness).unwrap();
}
