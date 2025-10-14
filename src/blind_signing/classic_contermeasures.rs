// Classic contermeasures : data display and conditional signature

use super::transaction::Transaction;

// Data display (clear signing)
pub fn display_transaction(tx: &Transaction) {
    println!("--- CLEAR SIGNING ---");
    println!("From   : {}", tx.from);
    println!("To     : {}", tx.to);
    println!("Amount : {} {}", tx.amount, tx.token);
    println!("Nonce  : {}", tx.nonce);
    println!("----------------------");
}

// Signature conditional signature
// Function that verifies if the transaction complies with a security policy

pub fn is_safe(tx: &Transaction) -> bool {
    let whitelist = ["0xSwapPool", "0xTrustedVault"]; // Static list of authorized recipients
    let allowed_tokens = ["USDC", "ETH"]; // Static list of authorized tokens

    // Return true if (amount <= 1000 and recipient in whitelist and token in allowed_token)
    tx.amount <= 1000
        && whitelist.contains(&tx.to.as_str())
        && allowed_tokens.contains(&tx.token.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_safe_valid_transaction() {
        // Check that a transaction compliant with the policy is considered safe
        let tx = Transaction {
            from: "0xAlice".to_string(),
            to: "0xSwapPool".to_string(),
            amount: 500,
            token: "USDC".to_string(),
            nonce: 1,
        };

        assert!(is_safe(&tx), "The transaction should be considered safe");
    }

    #[test]
    fn test_is_safe_exceeds_amount() {
        //  Check that a transaction with an amount that is too high is rejected
        let tx = Transaction {
            from: "0xAlice".to_string(),
            to: "0xSwapPool".to_string(),
            amount: 5000,
            token: "USDC".to_string(),
            nonce: 2,
        };

        assert!(
            !is_safe(&tx),
            "The transaction should be rejected because of the amount"
        );
    }

    #[test]
    fn test_is_safe_invalid_recipient() {
        // Verifies that a transaction with an unauthorized recipient is rejected
        let tx = Transaction {
            from: "0xAlice".to_string(),
            to: "0xUnknownVault".to_string(),
            amount: 500,
            token: "USDC".to_string(),
            nonce: 3,
        };

        assert!(
            !is_safe(&tx),
            "The transaction should be rejected because of the recipient"
        );
    }

    #[test]
    fn test_is_safe_invalid_token() {
        // Verifies that a transaction with an unauthorized token is rejected
        let tx = Transaction {
            from: "0xAlice".to_string(),
            to: "0xSwapPool".to_string(),
            amount: 500,
            token: "DAI".to_string(),
            nonce: 4,
        };

        assert!(
            !is_safe(&tx),
            "The transaction should be rejected because of the token"
        );
    }

    #[test]
    fn test_display_transaction_output_format() {
        // Check that the transaction display does not panic and follows the expected format
        let tx = Transaction {
            from: "0xAlice".to_string(),
            to: "0xSwapPool".to_string(),
            amount: 250,
            token: "ETH".to_string(),
            nonce: 99,
        };

        // This test simply checks that the function runs without error
        display_transaction(&tx);
    }
}
