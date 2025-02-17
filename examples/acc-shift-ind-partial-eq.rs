use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::{
	constraint_system::validate::validate_witness, oracle::ShiftVariant,
	transparent::shift_ind::ShiftIndPartialEval,
};
use binius_field::{arch::OptimalUnderlier, util::eq, BinaryField128b, Field};

type U = OptimalUnderlier;
type F128 = BinaryField128b;

// ShiftIndPartialEval is a more elaborated version of EqIndPartialEval. Same idea with challenges, but a bit more
// elaborated evaluation algorithm is used
fn main() {
	let allocator = bumpalo::Bump::new();
	let mut builder = ConstraintSystemBuilder::<U, F128>::new_with_witness(&allocator);

	let block_size = 3;
	let shift_offset = 4;
	// Challenges have to be F128, but actual values in the witness could be of smaller field
	let challenges = vec![
		F128::new(0xff00ff00ff00ff00ff00ff00ff00ff00),
		F128::new(0x1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f),
		F128::new(0x2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f),
	];
	let shift_variant = ShiftVariant::LogicalLeft;

	assert_eq!(block_size, challenges.len());

	let shift_ind =
		ShiftIndPartialEval::new(block_size, shift_offset, shift_variant, challenges.clone())
			.unwrap();

	let transparent = builder.add_transparent("shift_ind", shift_ind).unwrap();

	if let Some(witness) = builder.witness() {
		let mut transparent_witness = witness.new_column::<F128>(transparent);
		let values = transparent_witness.as_mut_slice::<u128>();

		let lexicographical_order_x = [
			vec![F128::new(0), F128::new(0), F128::new(0)],
			vec![F128::new(1), F128::new(0), F128::new(0)],
			vec![F128::new(0), F128::new(1), F128::new(0)],
			vec![F128::new(1), F128::new(1), F128::new(0)],
			vec![F128::new(0), F128::new(0), F128::new(1)],
			vec![F128::new(1), F128::new(0), F128::new(1)],
			vec![F128::new(0), F128::new(1), F128::new(1)],
			vec![F128::new(1), F128::new(1), F128::new(1)],
		];

		assert_eq!(lexicographical_order_x.len(), 1 << block_size);

		for (val, x) in values.iter_mut().zip(lexicographical_order_x.into_iter()) {
			*val = compute(block_size, shift_offset, shift_variant, x, challenges.clone()).val();
		}
	}

	let witness = builder.take_witness().unwrap();
	let constraints_system = builder.build().unwrap();

	validate_witness(&constraints_system, &[], &witness).unwrap();
}

// Evaluation logic taken from ShiftIndPartialEval implementation
fn compute(
	block_size: usize,
	shift_offset: usize,
	shift_variant: ShiftVariant,
	x: Vec<F128>,
	y: Vec<F128>,
) -> F128 {
	let (mut s_ind_p, mut s_ind_pp) = (F128::ONE, F128::ZERO);
	let (mut temp_p, mut temp_pp) = (F128::default(), F128::default());
	(0..block_size).for_each(|k| {
		let o_k = shift_offset >> k;
		let product = x[k] * y[k];
		if o_k % 2 == 1 {
			temp_p = (y[k] - product) * s_ind_p;
			temp_pp = (x[k] - product) * s_ind_p + eq(x[k], y[k]) * s_ind_pp;
		} else {
			temp_p = eq(x[k], y[k]) * s_ind_p + (y[k] - product) * s_ind_pp;
			temp_pp = (x[k] - product) * s_ind_pp;
		}
		// roll over results
		s_ind_p = temp_p;
		s_ind_pp = temp_pp;
	});

	match shift_variant {
		ShiftVariant::CircularLeft => s_ind_p + s_ind_pp,
		ShiftVariant::LogicalLeft => s_ind_p,
		ShiftVariant::LogicalRight => s_ind_pp,
	}
}
