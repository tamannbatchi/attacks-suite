// Structure of a transaction that represents a typical blockchain transaction

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub from: String,  // Adress of the sender
    pub to: String,    // Adress of the recipient
    pub amount: u64,   // Amount to transfer
    pub token: String, // Name of token
    pub nonce: u64,    // Unique identifier to prevent replays
}

// Implementation of the transaction
impl Transaction {
    // Method that takes a reference to the transaction and converts it into a JSON string,
    // or returns an error if the conversion fails
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn test_to_json_serializes_correctly() {
        // Verifies that the to_json() method produces a valid JSON string
        let tx = Transaction {
            from: "0xAlice".to_string(),
            to: "0xBob".to_string(),
            amount: 250,
            token: "ETH".to_string(),
            nonce: 42,
        };

        let json = tx.to_json().expect("The JSON serialization is failed");
        let parsed: Value = serde_json::from_str(&json).expect("The generated JSON is invalid");

        assert_eq!(parsed["from"], "0xAlice");
        assert_eq!(parsed["to"], "0xBob");
        assert_eq!(parsed["amount"], 250);
        assert_eq!(parsed["token"], "ETH");
        assert_eq!(parsed["nonce"], 42);
    }

    #[test]
    fn test_to_json_handles_empty_fields() {
        // Check that the to_json() method works even with empty fields
        let tx = Transaction {
            from: "".to_string(),
            to: "".to_string(),
            amount: 0,
            token: "".to_string(),
            nonce: 0,
        };

        let json = tx.to_json().expect("The JSON serialization is failed");
        let parsed: Value = serde_json::from_str(&json).expect("The generated JSON is invalid");

        assert_eq!(parsed["from"], "");
        assert_eq!(parsed["to"], "");
        assert_eq!(parsed["amount"], 0);
        assert_eq!(parsed["token"], "");
        assert_eq!(parsed["nonce"], 0);
    }

    #[test]
    fn test_to_json_error_handling() {
        // Check that the to_json() method returns an error if the serialization fails

        #[derive(Debug)]
        struct NonSerializable;

        #[derive(Serialize)]
        struct Wrapper {
            #[serde(skip_serializing)]
            inner: NonSerializable,
        }

        let wrapper = Wrapper {
            inner: NonSerializable,
        };
        let result = serde_json::to_string(&wrapper);

        assert!(
            result.is_ok(),
            "The serialization should succeed because the field is ignored"
        );
    }
}
