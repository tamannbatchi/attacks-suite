// This code defines an R1CS circuit in Rust with Arkworks,
// which encodes a conditional signature policy within a ZKP framework.

use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::uint64::UInt64;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// boolean gadget : return true if `a < b`
fn is_less_than(a: &UInt64<Fr>, b: &UInt64<Fr>) -> Result<Boolean<Fr>, SynthesisError> {
    let a_bits = a.to_bits_le();
    let b_bits = b.to_bits_le();

    let mut result = Boolean::constant(false);
    for (abit, bbit) in a_bits.iter().rev().zip(b_bits.iter().rev()) {
        let lt = abit.not().and(bbit)?; // a=0, b=1 → a < b
        let gt = abit.and(&bbit.not())?; // a=1, b=0 → a > b
        result = lt.or(&result.not().and(&gt.not())?.and(&result)?)?;
    }

    Ok(result)
}

/// Constraint : `amount < threshold`
pub fn enforce_amount_less_than(amount: &UInt64<Fr>, threshold: u64) -> Result<(), SynthesisError> {
    let threshold_var = UInt64::constant(threshold);
    let is_less = is_less_than(amount, &threshold_var)?;
    is_less.enforce_equal(&Boolean::constant(true))?;
    Ok(())
}

// Structure representing the input data of the circuit
#[derive(Clone)]
pub struct TxCircuit {
    pub amount: u64,     // Amount of the transaction
    pub to_hash: u64,    // Hash or identifier of recipient
    pub token_hash: u64, // Hash or identifier of token
}

// ConstraintSynthesizer is a trait to implement to define a R1CS circuit
// implementation of the trait ConstraintSynthesizer for TxCircuit on the field Fr
impl ConstraintSynthesizer<Fr> for TxCircuit {
    // Main method of the circuit that takes a reference to the constraint system and returns a Result
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocation of the three variables in the circuit
        // (this variables are the non public witnesses)
        let amount_var = UInt64::new_witness(cs.clone(), || Ok(self.amount))?;
        let to_var = UInt64::new_witness(cs.clone(), || Ok(self.to_hash))?;
        let token_var = UInt64::new_witness(cs.clone(), || Ok(self.token_hash))?;

        // Verification of the amount
        // it is required that amount_var <= 1000,
        // We therefore create an R1CS instance that encodes this comparison
        enforce_amount_less_than(&amount_var, 1000)?;

        // Verification of the recipient
        // We verifie that to_var is equal to 12345 ou 67890
        // It is required that the result is true
        // we therefore create a whitelist of recipient in the circuit
        let valid_to = to_var
            .is_eq(&UInt64::constant(12345))?
            .or(&to_var.is_eq(&UInt64::constant(67890))?)?;
        valid_to.enforce_equal(&Boolean::constant(true))?;

        // Verification of token
        // we verifie that token_var is equal to 111 or 222
        // It is required that the result is true
        // we therefore create a whitelist of tokens in the circuit
        let valid_token = token_var
            .is_eq(&UInt64::constant(111))?
            .or(&token_var.is_eq(&UInt64::constant(222))?)?;
        valid_token.enforce_equal(&Boolean::constant(true))?;

        // if all constraints are satisfied,
        // the circuit return Ok, else a synthesis error is raised
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    #[test]
    fn test_amount_too_high_fails_constraints() {
        // Verifie that a transaction with an amount too high fails
        let cs = ConstraintSystem::<Fr>::new_ref();

        let circuit = TxCircuit {
            amount: 5000, // exceeds the threshold
            to_hash: 12345,
            token_hash: 111,
        };

        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "the circuit must not be satisfied if the amount exceeds the threshold"
        );
    }

    #[test]
    fn test_invalid_recipient_fails_constraints() {
        //  Verifie that an unauthorized recipient fails
        let cs = ConstraintSystem::<Fr>::new_ref();

        let circuit = TxCircuit {
            amount: 500,
            to_hash: 99999, // non whitelisted
            token_hash: 111,
        };

        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "The circuit must not be satisfied if the recipient is invalid"
        );
    }

    #[test]
    fn test_invalid_token_fails_constraints() {
        //  Verifie that an unauthorized token fails
        let cs = ConstraintSystem::<Fr>::new_ref();

        let circuit = TxCircuit {
            amount: 500,
            to_hash: 12345,
            token_hash: 999, // non whitelisted
        };

        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "The circuit must not be satisfied if the token is invalid"
        );
    }
}
