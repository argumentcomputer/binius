use binius_circuits::{builder::ConstraintSystemBuilder, unconstrained::unconstrained};
use binius_core::{constraint_system::validate::validate_witness, oracle::OracleId};
use binius_field::{
	arch::OptimalUnderlier, packed::set_packed_slice, BinaryField128b, BinaryField1b,
	BinaryField8b, ExtensionField, TowerField,
};
use binius_macros::arith_expr;

type U = OptimalUnderlier;
type F128 = BinaryField128b;
type F8 = BinaryField8b;
type F1 = BinaryField1b;

// FIXME: Following gadgets are unconstrained. Only for demonstrative purpose, don't use in production

fn bytes_decomposition_gadget(
	builder: &mut ConstraintSystemBuilder<U, F128>,
	name: impl ToString,
	log_size: usize,
	input: OracleId,
) -> Result<OracleId, anyhow::Error> {
	builder.push_namespace(name);

	// Define 8 separate variables that represent bits (F1) of the particular byte behind `input` variable
	let output_bits: [OracleId; 8] =
		builder.add_committed_multiple("output_bits", log_size, F1::TOWER_LEVEL);

	let coefficients: [OracleId; 8] =
		builder.add_committed_multiple("coeffs", log_size, F8::TOWER_LEVEL);

	let coeff_vals = [
		F8::new(0b00000001),
		F8::new(0b00000010),
		F8::new(0b00000100),
		F8::new(0b00001000),
		F8::new(0b00010000),
		F8::new(0b00100000),
		F8::new(0b01000000),
		F8::new(0b10000000),
	];

	// Define `output` variable that will store `input` bytes (we will compare this in our constraint below).
	// Since we want to enforce decomposition, we use `LinearCombination` column which naturally fits for this purpose.
	// We need to specify our coefficients now and later take care of defining bit columns and setting bit values appropriately
	let output = builder.add_linear_combination(
		"output",
		log_size,
		(0..8).map(|b| {
			// Our coefficients are:
			//
			// 00000001
			// 00000010
			// 00000100
			// 00001000
			// 00010000
			// 00100000
			// 01000000
			// 10000000
			//
			let basis =
				<F8 as ExtensionField<F1>>::basis(b).expect("index is less than extension degree");
			(output_bits[b], basis.into())
		}),
	)?;

	if let Some(witness) = builder.witness() {
		// Let's get actual value of bytes from memory of `input` variable
		let input = witness.get::<F8>(input)?.as_slice::<F8>();

		// Create exactly 8 columns in the witness each representing 1 bit from decomposition
		let mut output_bits_witness: [_; 8] = output_bits.map(|id| witness.new_column::<F1>(id));

		// Here we use packed type. Since constraint system is instantiated with F128, the packed type for our bits would be Packed128x1
		let output_bits = output_bits_witness.each_mut().map(|bit| bit.packed());

		// Create 1 column where we will write bytes from input to compare in the constraint later
		let mut output = witness.new_column::<F8>(output);

		// Get its memory
		let output = output.as_mut_slice::<F8>();

		// Write coefficients into the witness
		let mut coeff_witness =
			coefficients.map(|coefficient| witness.new_column::<F8>(coefficient));
		let coeff_witness = coeff_witness
			.each_mut()
			.map(|coeff| coeff.as_mut_slice::<F8>());
		for (idx, v) in coeff_witness.into_iter().enumerate() {
			for vv in v {
				*vv = coeff_vals[idx];
			}
		}

		// For each byte from the `input` we need to just copy it to the `output` and also
		// we need to perform actual decomposition and write it in a form of packed bits to the `output_bits`
		for z in 0..input.len() {
			output[z] = input[z];

			// Decompose particular byte value from the 'input'
			let input_bits_bases = ExtensionField::<F1>::iter_bases(&input[z]);

			// Write decomposed bits to the memory of `output_bits` which expects them in the form of Packed128x1.
			// It is important step, since our `output` variable is actually composed from `output_bits`
			// and it expects to contain exactly the result of executing linear combination over bits stored
			// behind `output_bits`
			for (b, bit) in input_bits_bases.enumerate() {
				set_packed_slice(output_bits[b], z, bit);
			}
		}
	}

	// We just assert that every byte from `input` equals to correspondent byte from `output`
	builder.assert_zero("s_box", [input, output], arith_expr!([i, o] = i - o).convert_field());

	// Assert decomposition
	builder.assert_zero(
		"decomposition",
		[
			input,
			output_bits[0],
			output_bits[1],
			output_bits[2],
			output_bits[3],
			output_bits[4],
			output_bits[5],
			output_bits[6],
			output_bits[7],
			coefficients[0],
			coefficients[1],
			coefficients[2],
			coefficients[3],
			coefficients[4],
			coefficients[5],
			coefficients[6],
			coefficients[7],
		],
		arith_expr!(
			[i, b0, b1, b2, b3, b4, b5, b6, b7, c0, c1, c2, c3, c4, c5, c6, c7] =
				b0 * c0 + b1 * c1 + b2 * c2 + b3 * c3 + b4 * c4 + b5 * c5 + b6 * c6 + b7 * c7 - i
		)
		.convert_field(),
	);

	builder.pop_namespace();
	Ok(output)
}

fn elder_4bits_masking_gadget(
	builder: &mut ConstraintSystemBuilder<U, F128>,
	name: impl ToString,
	log_size: usize,
	input: OracleId,
) -> Result<OracleId, anyhow::Error> {
	builder.push_namespace(name);
	let output_bits: [OracleId; 8] =
		builder.add_committed_multiple("output_bits", log_size, F1::TOWER_LEVEL);

	// we want to mask 4 elder bits in input byte
	let lc_coefficients = [
		F8::new(0b00000001),
		F8::new(0b00000010),
		F8::new(0b00000100),
		F8::new(0b00001000),
		F8::new(0b00000000),
		F8::new(0b00000000),
		F8::new(0b00000000),
		F8::new(0b00000000),
	];

	let coefficients: [OracleId; 8] =
		builder.add_committed_multiple("coeffs", log_size, F8::TOWER_LEVEL);

	let output = builder.add_linear_combination(
		"output",
		log_size,
		(0..8).map(|b| (output_bits[b], lc_coefficients[b].into())),
	)?;

	if let Some(witness) = builder.witness() {
		// Write coefficients into the witness
		let mut coeff_witness =
			coefficients.map(|coefficient| witness.new_column::<F8>(coefficient));
		let coeff_witness = coeff_witness
			.each_mut()
			.map(|coeff| coeff.as_mut_slice::<F8>());
		for (idx, v) in coeff_witness.into_iter().enumerate() {
			for vv in v {
				*vv = lc_coefficients[idx];
			}
		}

		let input = witness.get::<F8>(input)?.as_slice::<F8>();
		let mut output_bits_witness: [_; 8] = output_bits.map(|id| witness.new_column::<F1>(id));
		let output_bits = output_bits_witness.each_mut().map(|bit| bit.packed());
		let mut output = witness.new_column::<F8>(output);
		let output = output.as_mut_slice::<F8>();
		for z in 0..input.len() {
			// apply mask to the input byte
			let byte_out_val = u8::from(input[z]) & 0x0F;
			output[z] = F8::from(byte_out_val);

			let input_bits_bases = ExtensionField::<F1>::iter_bases(&input[z]);
			for (b, bit) in input_bits_bases.enumerate() {
				set_packed_slice(output_bits[b], z, bit);
			}
		}
	}

	// Assert decomposition
	builder.assert_zero(
		"decomposition",
		[
			output,
			output_bits[0],
			output_bits[1],
			output_bits[2],
			output_bits[3],
			output_bits[4],
			output_bits[5],
			output_bits[6],
			output_bits[7],
			coefficients[0],
			coefficients[1],
			coefficients[2],
			coefficients[3],
			coefficients[4],
			coefficients[5],
			coefficients[6],
			coefficients[7],
		],
		arith_expr!(
			[o, b0, b1, b2, b3, b4, b5, b6, b7, c0, c1, c2, c3, c4, c5, c6, c7] =
				b0 * c0 + b1 * c1 + b2 * c2 + b3 * c3 + b4 * c4 + b5 * c5 + b6 * c6 + b7 * c7 - o
		)
		.convert_field(),
	);

	builder.pop_namespace();
	Ok(output)
}

fn main() {
	let allocator = bumpalo::Bump::new();
	let mut builder = ConstraintSystemBuilder::<U, F128>::new_with_witness(&allocator);

	let log_size = 1usize;

	// Define set of bytes that we want to decompose
	let p_in = unconstrained::<U, F128, F8>(&mut builder, "p_in".to_string(), log_size).unwrap();

	let _ =
		bytes_decomposition_gadget(&mut builder, "bytes decomposition", log_size, p_in).unwrap();

	let _ = elder_4bits_masking_gadget(&mut builder, "masking", log_size, p_in).unwrap();

	let witness = builder.take_witness().unwrap();
	let cs = builder.build().unwrap();

	validate_witness(&cs, &[], &witness).unwrap();
}
