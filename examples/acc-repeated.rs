use binius_circuits::{builder::ConstraintSystemBuilder, unconstrained::unconstrained};
use binius_core::constraint_system::validate::validate_witness;
use binius_field::{
	arch::OptimalUnderlier, packed::set_packed_slice, BinaryField128b, BinaryField1b,
	BinaryField8b, PackedBinaryField128x1b,
};

type U = OptimalUnderlier;
type F128 = BinaryField128b;
type F8 = BinaryField8b;
type F1 = BinaryField1b;

// FIXME: Following gadgets are unconstrained. Only for demonstrative purpose, don't use in production

const LOG_SIZE: usize = 8;

// The idea of 'Repeated' column is that one can just copy data from initial column multiple times,
// so new column is X times bigger than original one. The following gadget operates over bytes, e.g.
// it creates column with some input bytes written and then creates one more 'Repeated' column
// where the same bytes are copied multiple times.
fn bytes_repeat_gadget(builder: &mut ConstraintSystemBuilder<U, F128>) {
	builder.push_namespace("bytes_repeat_gadget");

	let bytes = unconstrained::<U, F128, F8>(builder, "input", LOG_SIZE).unwrap();

	let repeat_times_log = 4usize;
	let repeating = builder
		.add_repeating("repeating", bytes, repeat_times_log)
		.unwrap();

	if let Some(witness) = builder.witness() {
		let input_values = witness.get::<F8>(bytes).unwrap().as_slice::<u8>();

		let mut repeating_witness = witness.new_column::<F8>(repeating);
		let repeating_values = repeating_witness.as_mut_slice::<u8>();

		let repeat_times = 2usize.pow(repeat_times_log as u32);
		assert_eq!(2usize.pow(LOG_SIZE as u32), input_values.len());
		assert_eq!(input_values.len() * repeat_times, repeating_values.len());

		for idx in 0..repeat_times {
			let start = idx * input_values.len();
			let end = start + input_values.len();
			repeating_values[start..end].copy_from_slice(input_values);
		}
	}

	builder.pop_namespace();
}

// Bit-oriented repeating is more elaborated due to a specifics of memory layout in Binius.
// In the following example, we use LOG_SIZE=8, which gives 2.pow(8) = 32 bytes written in the memory
// layout. This gives 32 * 8 = 256 bits of input information. Having that Repeated' column
// is instantiated with 'repeat_times_log = 2', this means that we have to repeat our bytes
// 2.pow(repeat_times_log) = 4 times ultimately. For setting bit values we use PackedBinaryField128x1b,
// so for 32 bytes (256 bits) of input data we use 2 PackedBinaryField128x1b elements. Considering 4
// repetitions Binius creates column with 8 PackedBinaryField128x1b elements totally.
// Proper writing bits requires separate iterating over PackedBinaryField128x1b elements and input bytes
// with extracting particular bit values from the input and setting appropriate bit in a given PackedBinaryField128x1b.
fn bits_repeat_gadget(builder: &mut ConstraintSystemBuilder<U, F128>) {
	builder.push_namespace("bits_repeat_gadget");

	let bits = unconstrained::<U, F128, F1>(builder, "input", LOG_SIZE).unwrap();
	let repeat_times_log = 2usize;

	// Binius will create column with appropriate height for us
	let repeating = builder
		.add_repeating("repeating", bits, repeat_times_log)
		.unwrap();

	if let Some(witness) = builder.witness() {
		let input_values = witness.get::<F1>(bits).unwrap().as_slice::<u8>();
		let mut repeating_witness = witness.new_column::<F1>(repeating);
		let output_values = repeating_witness.packed();

		// this performs writing input bits exactly 1 time. Depending on number of repetitions we
		// need to call this multiple times, providing offset for output values (PackedBinaryField128x1b elements)
		fn write_input(
			input_values: &[u8],
			output_values: &mut [PackedBinaryField128x1b],
			output_packed_offset: usize,
		) {
			let mut output_index = output_packed_offset;
			for (input_index, _) in (0..input_values.len()).enumerate() {
				let byte = input_values[input_index];

				set_packed_slice(output_values, output_index, F1::from(byte));
				set_packed_slice(output_values, output_index + 1, F1::from((byte >> 1) & 0x01));
				set_packed_slice(output_values, output_index + 2, F1::from((byte >> 2) & 0x01));
				set_packed_slice(output_values, output_index + 3, F1::from((byte >> 3) & 0x01));
				set_packed_slice(output_values, output_index + 4, F1::from((byte >> 4) & 0x01));
				set_packed_slice(output_values, output_index + 5, F1::from((byte >> 5) & 0x01));
				set_packed_slice(output_values, output_index + 6, F1::from((byte >> 6) & 0x01));
				set_packed_slice(output_values, output_index + 7, F1::from((byte >> 7) & 0x01));

				output_index += 8;
			}
		}

		let repeat_times = 2u32.pow(repeat_times_log as u32);

		let mut offset = 0;
		for _ in 0..repeat_times {
			write_input(input_values, output_values, offset);
			offset += input_values.len() * 8;
		}
	}

	builder.pop_namespace();
}

fn main() {
	let allocator = bumpalo::Bump::new();

	let mut builder = ConstraintSystemBuilder::<U, F128>::new_with_witness(&allocator);

	bytes_repeat_gadget(&mut builder);
	bits_repeat_gadget(&mut builder);

	let witness = builder.take_witness().unwrap();
	let cs = builder.build().unwrap();

	validate_witness(&cs, &[], &witness).unwrap();
}
