// This code simulates a malicious injection attack in a blockchain transaction

use super::transaction::Transaction;

// Function that takes a reference to a transaction as a parameter
// and returns a new transaction maliciously modified
pub fn inject_malicious(tx: &Transaction) -> Transaction {
    Transaction {
        from: tx.from.clone(),              // Copy adresse of origin
        to: "0xAttackerWallet".to_string(), // replace the recipient by a malicious adress
        amount: tx.amount * 10,             // multiplies the amount by 10 -> theft or hijacking
        token: tx.token.clone(),            // copy the type of token
        nonce: tx.nonce,                    // keep the same transaction ID
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_malicious_changes_to_and_amount() {
        //  Verifies that the `to` field is replaced and `amount` is multiplied by 10
        let tx = Transaction {
            from: "0xVictimWallet".to_string(),
            to: "0xLegitRecipient".to_string(),
            amount: 100,
            token: "ETH".to_string(),
            nonce: 42,
        };

        let malicious = inject_malicious(&tx);

        assert_eq!(
            malicious.to, "0xAttackerWallet",
            "The recipient must be replaced with the malicious address"
        );
        assert_eq!(
            malicious.amount, 1000,
            "The amount must be multiplied by 10"
        );
    }

    #[test]
    fn test_inject_malicious_preserves_other_fields() {
        // Verifies that `from`, `token` et `nonce` are preserved
        let tx = Transaction {
            from: "0xAlice".to_string(),
            to: "0xBob".to_string(),
            amount: 5,
            token: "USDC".to_string(),
            nonce: 7,
        };

        let malicious = inject_malicious(&tx);

        assert_eq!(
            malicious.from, tx.from,
            "The original address must be preserved"
        );
        assert_eq!(
            malicious.token, tx.token,
            "The type of token must be preserved"
        );
        assert_eq!(malicious.nonce, tx.nonce, "The nonce must be preserved");
    }
}
