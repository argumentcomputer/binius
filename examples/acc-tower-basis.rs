use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::{
	constraint_system::validate::validate_witness, transparent::tower_basis::TowerBasis,
};
use binius_field::{arch::OptimalUnderlier, BinaryField128b, Field, TowerField};

type U = OptimalUnderlier;
type F128 = BinaryField128b;

// TowerBasis expects actually basis vectors written to the witness.
// The form of basis could vary depending on 'iota' and 'k' parameters
fn main() {
	let allocator = bumpalo::Bump::new();
	let mut builder = ConstraintSystemBuilder::<U, F128>::new_with_witness(&allocator);

	let k = 3usize;
	let iota = 4usize;

	assert!(k + iota < 8);

	let tower_basis = TowerBasis::new(k, iota).unwrap();
	let transparent = builder.add_transparent("tower_basis", tower_basis).unwrap();

	if let Some(witness) = builder.witness() {
		let mut transparent_witness = witness.new_column::<F128>(transparent);
		let values = transparent_witness.as_mut_slice::<u128>();

		let lexicographic_query = [
			vec![F128::new(0), F128::new(0), F128::new(0)],
			vec![F128::new(1), F128::new(0), F128::new(0)],
			vec![F128::new(0), F128::new(1), F128::new(0)],
			vec![F128::new(1), F128::new(1), F128::new(0)],
			vec![F128::new(0), F128::new(0), F128::new(1)],
			vec![F128::new(1), F128::new(0), F128::new(1)],
			vec![F128::new(0), F128::new(1), F128::new(1)],
			vec![F128::new(1), F128::new(1), F128::new(1)],
		];

		assert_eq!(lexicographic_query.len(), 1 << k);

		for (val, query) in values.iter_mut().zip(lexicographic_query.into_iter()) {
			*val = compute(iota, query).val();
		}
	}

	let witness = builder.take_witness().unwrap();
	let constraints_system = builder.build().unwrap();

	validate_witness(&constraints_system, &[], &witness).unwrap();
}

fn compute(iota: usize, query: Vec<F128>) -> F128 {
	let mut result = F128::ONE;
	for (i, query_i) in query.iter().enumerate() {
		let r_comp = F128::ONE - query_i;
		let basis_elt = <F128 as TowerField>::basis(iota + i, 1).unwrap();
		result *= r_comp + *query_i * basis_elt;
	}
	result
}
