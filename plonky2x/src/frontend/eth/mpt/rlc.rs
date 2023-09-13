use std::marker::PhantomData;

use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::challenger::RecursiveChallenger;

use super::generators::SubarrayEqualGenerator;
use crate::prelude::{BoolVariable, ByteVariable, CircuitBuilder, PlonkParameters, Variable};

// @TODO(xearty): put this elsewhere
const MAX_ELEMENTS: u64 = 64;

impl<L: PlonkParameters<D>, const D: usize> CircuitBuilder<L, D> {
    fn commit_subarray(
        &mut self,
        arr: &[ByteVariable],
        offset: Variable,
        len: Variable,
        random_variables: &[Variable; MAX_ELEMENTS]
    ) -> Variable {
        let one = self.one();
        let end_idx = bulder.add(offset, len);
        let mut is_within_subarray = BoolVariable(self.zero());
        let mut commitment = self.zero();

        let idx_target = self.zero();
        for idx in 0..MAX_ELEMENTS {
            // is_within_subarray is one if idx is in the range [offset..offset+len]
            let is_at_start_idx = self.is_equal(idx_target, offset);
            is_within_subarray = self.add(is_within_subarray, at_start_idx);
            let is_at_end_idx = self.is_equal(idx_target, end_idx);
            is_within_subarray = self.sub(is_within_subarray, is_at_end_idx);

            // if in range, include the byte, multiplied by a random value
            let subarray_idx = self.mul(self.sub(idx_target, offset), is_within_subarray);
            let random_value_if_in_range = self.mul(is_within_subarray, self.mul(a[idx], random_variables[idx]));
            commitment = self.add(commitment, random_value_if_in_range);

            idx_target = self.add(idx_target, one);
        }

        commitment
    }

    #[allow(unused_variables, dead_code)]
    pub fn subarray_equal(
        &mut self,
        a: &[ByteVariable],
        a_offset: Variable,
        b: &[ByteVariable],
        b_offset: Variable,
        len: Variable,
    ) -> BoolVariable {
        let mut challenger = RecursiveChallenger::<L::Field, PoseidonHash, D>::new(&mut self.api);
        let challenger_seed = Vec::new();
        challenger.observe_elements(&challenger_seed);
        let random_variables = challenger.get_n_challenges(&mut self.api, MAX_ELEMENTS);

        let commitment_for_a = self.commit_subarray(a, a_offset, len, random_variables);
        let commitment_for_b = self.commit_subarray(b, b_offset, len, random_variables);
        self.is_equal(commitment_for_a, commitment_for_b)
    }

    #[allow(unused_variables, dead_code)]
    pub fn assert_subarray_equal(
        &mut self,
        a: &[ByteVariable],
        a_offset: Variable,
        b: &[ByteVariable],
        b_offset: Variable,
        len: Variable,
    ) {
        self.api.assert_bool(subarray_equal(&a, a_offset, &b, b_offset, len));
    }
}

pub(crate) mod tests {
    // TODO add a test for subarray_equal
}
