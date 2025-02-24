use binius_circuits::{builder::ConstraintSystemBuilder, sha256::u32const_repeating};
use binius_core::{
	constraint_system::validate::validate_witness, oracle::OracleId,
	transparent::constant::Constant,
};
use binius_field::{BinaryField1b, BinaryField32b};
type F32 = BinaryField32b;
type F1 = BinaryField1b;

const LOG_SIZE: usize = 4;

// FIXME: Following gadgets are unconstrained. Only for demonstrative purpose, don't use in production

fn constants_gadget(
	name: impl ToString,
	log_size: usize,
	builder: &mut ConstraintSystemBuilder,
	constant_value: u32,
) -> OracleId {
	builder.push_namespace(name);

	let c = Constant::new(log_size, F32::new(constant_value));

	let oracle = builder.add_transparent("constant", c).unwrap();

	if let Some(witness) = builder.witness() {
		let mut oracle_witness = witness.new_column::<F32>(oracle);
		let values = oracle_witness.as_mut_slice::<u32>();
		for v in values {
			*v = constant_value;
		}
	}

	builder.pop_namespace();

	oracle
}

// Transparent column can also naturally be used for storing some constants (also available for verifier).
// For example there is a 'u32const_repeating' function (in sha256 gadget) that does exactly this
// using Transparent + Repeated columns. Alternatively one can use Constant abstraction to create equivalent
// Transparent column.
fn main() {
	let allocator = bumpalo::Bump::new();

	let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);

	pub const SHA256_INIT: [u32; 8] = [
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
		0x5be0cd19,
	];

	let oracles: [OracleId; 8] =
		SHA256_INIT.map(|c| u32const_repeating(LOG_SIZE, &mut builder, c, "INIT").unwrap());
	if let Some(witness) = builder.witness() {
		for (index, oracle) in oracles.into_iter().enumerate() {
			let values = witness.get::<F1>(oracle).unwrap().as_slice::<u32>();

			// every value in the column should match the expected one
			for value in values {
				assert_eq!(*value, SHA256_INIT[index]);
			}
		}
	}

	let oracles: [OracleId; 8] =
		SHA256_INIT.map(|c| constants_gadget("constants_gadget", LOG_SIZE, &mut builder, c));
	if let Some(witness) = builder.witness() {
		for (index, oracle) in oracles.into_iter().enumerate() {
			// The difference is here. With Constant we have to operate over F32, while
			// with Transparent + Repeated approach as in 'u32const_repeating' we operate over F1,
			// which can be more convenient in the bit-oriented computations
			let values = witness.get::<F32>(oracle).unwrap().as_slice::<u32>();

			// every value in the column should match the expected one
			for value in values {
				assert_eq!(*value, SHA256_INIT[index]);
			}
		}
	}

	let witness = builder.take_witness().unwrap();
	let constraints_system = builder.build().unwrap();

	validate_witness(&constraints_system, &[], &witness).unwrap();
}
