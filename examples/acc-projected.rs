use binius_circuits::{builder::ConstraintSystemBuilder, unconstrained::unconstrained};
use binius_core::{constraint_system::validate::validate_witness, oracle::ProjectionVariant};
use binius_field::{BinaryField128b, BinaryField8b};

type F128 = BinaryField128b;
type F8 = BinaryField8b;

#[derive(Clone)]
struct U8U128ProjectionInfo {
	log_size: usize,
	decimal: usize,
	binary: Vec<F128>,
	variant: ProjectionVariant,
}

// The idea behind projection is that data from a column of some given field (F8)
// can be interpreted as a data of some or greater field (F128) and written to another column with equal or smaller length,
// which depends on LOG_SIZE and values of projection. Also two possible variants of projections are available, which
// has significant impact on input data processing.
// In the following example we have input column with bytes (u8) projected to the output column with u128 values.
fn projection(
	builder: &mut ConstraintSystemBuilder,
	projection_info: U8U128ProjectionInfo,
	namespace: &str,
) {
	builder.push_namespace(format!("projection {}", namespace));

	let input = unconstrained::<F8>(builder, "in", projection_info.clone().log_size).unwrap();

	let projected = builder
		.add_projected(
			"projected",
			input,
			projection_info.clone().binary,
			projection_info.clone().variant,
		)
		.unwrap();

	if let Some(witness) = builder.witness() {
		let input_values = witness.get::<F8>(input).unwrap().as_slice::<u8>();
		let mut projected_witness = witness.new_column::<F128>(projected);
		let projected_values = projected_witness.as_mut_slice::<F128>();

		assert_eq!(projected_values.len(), projection_info.expected_projection_len());

		match projection_info.variant {
			ProjectionVariant::FirstVars => {
				// Quite elaborated regularity, on my opinion
				for idx in 0..projected_values.len() {
					projected_values[idx] = F128::new(
						input_values[(idx
							* 2usize.pow(projection_info.clone().binary.len() as u32))
							+ projection_info.clone().decimal] as u128,
					);
				}
			}
			ProjectionVariant::LastVars => {
				// decimal representation of the binary values is used as a simple offset
				for idx in 0..projected_values.len() {
					projected_values[idx] =
						F128::new(input_values[projection_info.clone().decimal + idx] as u128);
				}
			}
		};
	}
	builder.pop_namespace();
}

impl U8U128ProjectionInfo {
	fn new(
		log_size: usize,
		decimal: usize,
		binary: Vec<F128>,
		variant: ProjectionVariant,
	) -> U8U128ProjectionInfo {
		assert!(log_size >= binary.len());

		if variant == ProjectionVariant::LastVars {
			// Pad with zeroes to LOG_SIZE len iterator.
			// In this case we interpret binary values in a reverse order, meaning that the very first
			// element is elder byte, so zeroes must be explicitly appended
			let mut binary_clone = binary.clone();
			let mut zeroes = vec![F128::new(0u128); log_size - binary.len()];
			binary_clone.append(&mut zeroes);

			let coefficients = (0..binary_clone.len())
				.map(|degree| F128::new(2usize.pow(degree as u32) as u128))
				.collect::<Vec<F128>>();

			let value = binary_clone
				.iter()
				.zip(coefficients.iter().rev())
				.fold(F128::new(0u128), |acc, (byte, coefficient)| acc + (*byte) * (*coefficient));

			assert_eq!(decimal as u128, value.val());
		}

		U8U128ProjectionInfo {
			log_size,
			decimal,
			binary,
			variant,
		}
	}

	fn expected_projection_len(&self) -> usize {
		2usize.pow((self.log_size - self.binary.len()) as u32)
	}
}

fn main() {
	let allocator = bumpalo::Bump::new();
	let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);

	let projection_data = U8U128ProjectionInfo::new(
		4usize,
		9usize,
		vec![
			F128::from(1u128),
			F128::from(0u128),
			F128::from(0u128),
			F128::from(1u128),
		],
		ProjectionVariant::FirstVars,
	);
	projection(&mut builder, projection_data, "test_1");

	let projection_data = U8U128ProjectionInfo::new(
		16usize,
		34816usize,
		vec![
			F128::from(1u128),
			F128::from(0u128),
			F128::from(0u128),
			F128::from(0u128),
			F128::from(1u128),
		],
		ProjectionVariant::LastVars,
	);
	projection(&mut builder, projection_data, "test_2");

	let projection_data = U8U128ProjectionInfo::new(
		4usize,
		15usize,
		vec![
			F128::from(1u128),
			F128::from(1u128),
			F128::from(1u128),
			F128::from(1u128),
		],
		ProjectionVariant::LastVars,
	);
	projection(&mut builder, projection_data, "test_3");

	let projection_data = U8U128ProjectionInfo::new(
		6usize,
		60usize,
		vec![
			F128::from(1u128),
			F128::from(1u128),
			F128::from(1u128),
			F128::from(1u128),
		],
		ProjectionVariant::LastVars,
	);
	/*
		With projection_data defined above we have 2^LOG_SIZE = 2^6 bytes in the input,
		the size of projection is computed as follows: 2.pow(LOG_SIZE - binary.len()) = 2.pow(6 - 4) = 4.
		the index of the input byte to use as projection is computed as follows (according to
		a LastVars projection variant regularity):

		idx + decimal, e.g.:

		0 + 60
		1 + 60
		2 + 60
		3 + 60

		where idx is [0..4].

		Memory layout:

		input: [a5, a2, b1, 60, 91, ed, 5e, fb, ae, 1c, b2, 14, 92, 73, 92, c8, 56, 6d, fa, de, a8, 46, 77, 48, e1, cc, 90, 75, 78, d5, 19, be, 0c, 86, 39, 28, 0c, cc, e9, 4e, 46, d9, 84, 65, 4a, a2, b4, 64, eb, 59, 7b, fd, 3f, 0e, 2d, ea, 06, 42, a9, ea, (19), (8f), (19), (52)], len: 64
		output: [
			BinaryField128b(0x00000000000000000000000000000019),
			BinaryField128b(0x0000000000000000000000000000008f),
			BinaryField128b(0x00000000000000000000000000000019),
			BinaryField128b(0x00000000000000000000000000000052)
		]
	*/
	projection(&mut builder, projection_data, "test_4");

	let projection_data = U8U128ProjectionInfo::new(
		4usize,
		15usize,
		vec![
			F128::from(1u128),
			F128::from(1u128),
			F128::from(1u128),
			F128::from(1u128),
		],
		ProjectionVariant::FirstVars,
	);
	projection(&mut builder, projection_data, "test_5");

	let projection_data = U8U128ProjectionInfo::new(
		6usize,
		13usize,
		vec![
			F128::from(1u128),
			F128::from(0u128),
			F128::from(1u128),
			F128::from(1u128),
		],
		ProjectionVariant::FirstVars,
	);
	/*
		With projection_data defined above we have 2^LOG_SIZE = 2^6 bytes in the input,
		the size of projection is computed as follows: 2.pow(LOG_SIZE - binary.len()) = 2.pow(6 - 4) = 4.
		the index of the input byte to use as projection is computed as follows:

		idx * 2usize.pow(binary.len()) + decimal, e.g.:

		0 * 2.pow(4) + 13 = 13, so input[13]
		1 * 2.pow(4) + 13 = 29, so input[29]
		2 * 2.pow(4) + 13 = 45, so input[45]
		3 * 2.pow(4) + 13 = 61, so input[61]

		where idx is [0..4] according to a FirstVars projection variant regularity.

		Memory layout:

		input: [18, d8, 58, d3, 24, f1, 8b, ec, 74, 1c, ab, 78, 13, (3e), 57, d7, 36, 15, 54, 50, 9a, cb, 98, 90, 58, cb, 79, 05, 83, (72), ea, 4d, f6, 3d, f3, 2f, af, e3, 32, 11, c9, 97, fb, ba, 24, (36), e9, 38, 7e, c7, a9, 68, bf, 31, 51, cf, 7b, 12, 20, 53, d8, (df), d7, cc], len: 64

		output: BinaryField128b(0x0000000000000000000000000000003e)
		output: BinaryField128b(0x00000000000000000000000000000072)
		output: BinaryField128b(0x00000000000000000000000000000036)
		output: BinaryField128b(0x000000000000000000000000000000df)
	*/
	projection(&mut builder, projection_data, "test_6");

	let witness = builder.take_witness().unwrap();
	let cs = builder.build().unwrap();

	validate_witness(&cs, &[], &witness).unwrap();
}
