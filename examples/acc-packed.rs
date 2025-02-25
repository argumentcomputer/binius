use binius_circuits::{builder::ConstraintSystemBuilder, unconstrained::unconstrained};
use binius_core::constraint_system::validate::validate_witness;
use binius_field::{BinaryField16b, BinaryField1b, BinaryField32b, BinaryField8b, TowerField};

type F32 = BinaryField32b;
type F16 = BinaryField16b;
type F8 = BinaryField8b;
type F1 = BinaryField1b;

// FIXME: Following gadgets are unconstrained. Only for demonstrative purpose, don't use in production

fn packing_32_bits_to_u32(builder: &mut ConstraintSystemBuilder) {
	builder.push_namespace("packing_32_bits_to_u32");

	let bits = unconstrained::<F1>(builder, "bits", F32::TOWER_LEVEL).unwrap();
	let packed = builder
		.add_packed("packed", bits, F32::TOWER_LEVEL)
		.unwrap();

	if let Some(witness) = builder.witness() {
		let bits = witness.get::<F1>(bits).unwrap();
		assert_eq!(bits.as_slice::<u8>().len(), 16); // 16x u8

		let composition = bits.repacked::<F32>();
		assert_eq!(composition.as_slice::<u32>().len(), 4); // 4x u32

		witness.set(packed, composition).unwrap();
	}

	// setting witness above is logically identical to the following "manual" data writing (using Little-Endian format):
	/*
		if let Some(witness) = builder.witness() {
			let bytes_values = witness.get::<F1>(bits).unwrap().as_slice::<u8>();

			let mut packed_witness = witness.new_column::<F32>(packed);
			let slice = packed_witness.as_mut_slice::<u32>();

			bytes_values.chunks(4).zip(slice.into_iter()).for_each(|(chunk, val)| {
				*val = u32::from_le_bytes(chunk.try_into().unwrap());
			});
		}
	*/

	builder.pop_namespace();
}

fn packing_4_bytes_to_u32(builder: &mut ConstraintSystemBuilder) {
	builder.push_namespace("packing_4_bytes_to_u32");

	let bytes = unconstrained::<F8>(builder, "bytes", F16::TOWER_LEVEL).unwrap();
	let packed = builder
		.add_packed("packed", bytes, F16::TOWER_LEVEL)
		.unwrap();

	// 'repacked' approach doesn't work for this case, so let's write data to the witness "manually"

	if let Some(witness) = builder.witness() {
		let bytes_val = witness.get::<F8>(bytes).unwrap().as_slice::<u8>();

		let mut packed_witness = witness.new_column::<F32>(packed);
		let slice = packed_witness.as_mut_slice::<u32>();

		bytes_val
			.chunks(4)
			.zip(slice.iter_mut())
			.for_each(|(chunk, val)| {
				*val = u32::from_le_bytes(chunk.try_into().unwrap());
			});
	}

	builder.pop_namespace();
}

fn packing_8_bits_to_u8(builder: &mut ConstraintSystemBuilder) {
	builder.push_namespace("packing_8_bits_to_u8");

	let bits = unconstrained::<F1>(builder, "bits", F8::TOWER_LEVEL).unwrap();
	let packed = builder.add_packed("packed", bits, F8::TOWER_LEVEL).unwrap();

	if let Some(witness) = builder.witness() {
		let bits_values = witness.get::<F1>(bits).unwrap();

		witness.set::<F8>(packed, bits_values.repacked()).unwrap();
	}

	builder.pop_namespace();
}

fn main() {
	let allocator = bumpalo::Bump::new();

	let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);

	packing_32_bits_to_u32(&mut builder);
	packing_4_bytes_to_u32(&mut builder);
	packing_8_bits_to_u8(&mut builder);

	let witness = builder.take_witness().unwrap();
	let cs = builder.build().unwrap();

	validate_witness(&cs, &[], &witness).unwrap();
}
