use bumpalo::Bump;
use binius_circuits::builder::ConstraintSystemBuilder;
use binius_circuits::unconstrained::fixed_u32;
use binius_core::constraint_system::channel::{Boundary, FlushDirection};
use binius_core::constraint_system::validate::validate_witness;
use binius_field::{BinaryField128b, BinaryField32b};

type F128 = BinaryField128b;
type F32 = BinaryField32b;

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];


// Permutation is a classic construction in a traditional cryptography. It has well-defined security properties
// and high performance due to implementation via lookups. One can possible to implement gadget for permutations using
// channels API from Binius. The following examples shows how to enforce Blake3 permutation - verifier pulls pairs of
// input/output of the permutation (encoded as a BinaryField128b elements, to reduce number of flushes),
// while prover is expected to push similar IO to make channel balanced.
fn permute(m: &mut [u32; 16]) {
    let mut permuted = [0; 16];
    for i in 0..16 {
        permuted[i] = m[MSG_PERMUTATION[i]];
    }
    *m = permuted;
}

fn main() {
    let log_size = 4usize;

    let allocator = Bump::new();
    let mut builder = ConstraintSystemBuilder::new_with_witness(&allocator);

    let m = [0xfffffff0, 0xfffffff1, 0xfffffff2, 0xfffffff3, 0xfffffff4, 0xfffffff5, 0xfffffff6, 0xfffffff7, 0xfffffff8, 0xfffffff9, 0xfffffffa, 0xfffffffb, 0xfffffffc, 0xfffffffd, 0xfffffffe, 0xffffffff];

    let mut m_clone = m.clone();
    permute(&mut m_clone);

    let expected = [0xfffffff2, 0xfffffff6, 0xfffffff3, 0xfffffffa, 0xfffffff7, 0xfffffff0, 0xfffffff4, 0xfffffffd, 0xfffffff1, 0xfffffffb, 0xfffffffc, 0xfffffff5, 0xfffffff9, 0xfffffffe, 0xffffffff, 0xfffffff8];
    assert_eq!(m_clone, expected);


    let u32_in = fixed_u32::<F32>(&mut builder, "in", log_size, m.to_vec()).unwrap();
    let u32_out = fixed_u32::<F32>(&mut builder, "out", log_size, expected.to_vec()).unwrap();

    // we pack 4-u32 (F32) tuples of permutation IO into F128 columns and use them for flushing
    let u128_in = builder.add_packed("in_packed", u32_in, 2).unwrap();
    let u128_out = builder.add_packed("out_packed", u32_out, 2).unwrap();

    // populate memory layout (witness)
    if let Some(witness) = builder.witness() {
        let in_f32 = witness.get::<F32>(u32_in).unwrap();
        let out_f32 = witness.get::<F32>(u32_out).unwrap();
        witness.new_column::<F128>(u128_in);
        witness.new_column::<F128>(u128_out);

        witness.set(u128_in, in_f32.repacked::<F128>()).unwrap();
        witness.set(u128_out, out_f32.repacked::<F128>()).unwrap();
    }

    let channel = builder.add_channel();
    // count defines how many values ( 0 .. count ) from a given columns to send (pushing to a channel)
    builder.send(channel, 4, [u128_in, u128_out]).unwrap();

    let witness = builder.take_witness().unwrap();
    let cs = builder.build().unwrap();

    // consider our 4-u32 values from a given tupple as 4 limbs of u128
    let f = |limb0: u32, limb1: u32, limb2: u32, limb3: u32| {
        let mut x = 0u128;

        x ^= (limb3 as u128) << 96;
        x ^= (limb2 as u128) << 64;
        x ^= (limb1 as u128) << 32;
        x ^= limb0 as u128;

        F128::new(x)
    };

    // Boundaries define actual data (encoded in a set of Flushes) that verifier can push or pull from a given channel
    // in order to check if prover is able to balance that channel
    let mut offset = 0usize;
    let boundaries = (0..4).into_iter().map(|_| {
        let boundary = Boundary {
            values: vec![
                f(m[offset], m[offset + 1], m[offset + 2], m[offset + 3]),
                f(expected[offset], expected[offset + 1], expected[offset + 2], expected[offset + 3])
            ],
            channel_id: channel,
            direction: FlushDirection::Pull,
            multiplicity: 1
        };
        offset += 4;
        boundary
    }).collect::<Vec<Boundary<F128>>>();

    validate_witness(&cs, &boundaries, &witness).unwrap();
}
