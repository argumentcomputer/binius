use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::{
	constraint_system::validate::validate_witness, transparent::eq_ind::EqIndPartialEval,
};
use binius_field::{BinaryField128b, PackedField};

type F128 = BinaryField128b;

const LOG_SIZE: usize = 3;

// FIXME: Following gadgets are unconstrained. Only for demonstrative purpose, don't use in production

// Currently, it is hard for me to imagine some real world use-cases where Transparent column specified by
// EqIndPartialEval could be useful. The program can use some of its data as challenges and the Transparent
// column with EqIndPartialEval will expect witness values defined as following:
//
// x_i * y_i + (1 - x_i) * (1 - y_i)
//
// where 'x_i' is an element from a particular row of basis matrix, and y_i is a given challenge.
//
fn main() {
	let allocator = bumpalo::Bump::new();

	let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);

	// A truth table [000, 001, 010, 011 ... 111] where each row is in reversed order
	let rev_basis = [
		vec![0, 0, 0],
		vec![1, 0, 0],
		vec![0, 1, 0],
		vec![1, 1, 0],
		vec![0, 0, 1],
		vec![1, 0, 1],
		vec![0, 1, 1],
		vec![1, 1, 1],
	];

	// rev_basis size correlates with LOG_SIZE
	assert_eq!(1 << LOG_SIZE, rev_basis.len());

	// let's choose some random challenges (each not greater than 1 << LOG_SIZE bits for this example)
	let challenges = vec![F128::from(110), F128::from(190), F128::from(200)];

	// challenges size correlates with LOG_SIZE
	assert_eq!(challenges.len(), LOG_SIZE);

	let eq_ind_partial_eval = EqIndPartialEval::new(challenges.clone());

	let id = builder
		.add_transparent("eq_ind_partial_eval", eq_ind_partial_eval)
		.unwrap();

	if let Some(witness) = builder.witness() {
		let mut eq_witness = witness.new_column::<F128>(id);

		let column_values = eq_witness.as_mut_slice::<F128>();
		assert_eq!(column_values.len(), 1 << LOG_SIZE);

		let one = F128::one();

		for (inv_basis_item, val) in rev_basis.iter().zip(column_values.iter_mut()) {
			let mut value = F128::one();
			inv_basis_item
				.iter()
				.zip(challenges.iter())
				.for_each(|(x, y)| {
					let x = F128::new(*x);
					let y = *y;

					// following expression is defined in the EqIndPartialEval implementation
					value *= x * y + (one - x) * (one - y);
				});
			*val = value;
		}
	}

	let witness = builder.take_witness().unwrap();
	let constraints_system = builder.build().unwrap();

	validate_witness(&constraints_system, &[], &witness).unwrap();
}
