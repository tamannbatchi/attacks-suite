# Cryptographic Attack Suite

_A multi-modular offensive framework targeting BIP32, ECDSA, and blind signing protocols through glitch injection, timing analysis, SCA based on deep learning, fault attacks and machine learning, blinding signing and countermeasures (classic and ZKP, ZK SNARK precisely)._

---

##  Purpose & Philosophy

This project is a **manifeste offensif** — a reproducible, narratively enriched suite of cryptographic attacks and mitigations.  
It is designed to simulate real-world vulnerabilities, recover secrets under constrained conditions, and benchmark the effectiveness of countermeasures.  
Every module is built for clarity, modularity, and strategic visibility.

---

##  What This Project Demonstrates

-  **Private key recovery via timing and fault analysis on hardened BIP32 derivation** 
  _By injecting faults or measuring execution time during hardened BIP32 derivation, the project recovers child private keys at specific indices — bypassing protections that normally prevent reverse engineering. This demonstrates that hardened derivation is not immune to side-channel exploitation._

-  **Nonce reuse detection and exploitation in ECDSA signatures** 
  _The suite identifies reused `r` values across ECDSA signatures and reconstructs the private key using `(r, s, z)` collisions. This attack is fully automated and reproducible, showcasing the critical importance of nonce uniqueness in digital signatures._

- **Blind signing attacks with classic and ZKP-based countermeasures** 
  _Blind signing scenarios are modeled to simulate cases where users unknowingly authorize malicious transactions. The project demonstrates how attackers can manipulate opaque payloads to bypass user consent, and benchmarks both classic countermeasures (display data, conditional signature) and advanced zero-knowledge defenses (zkSNARKs) to restore verifiability and trust._

-  **Machine Learning-based classification and secret recovery from fault traces** 
  _Using Smartcore, the project trains classifiers on fault-injected traces to predict secret-dependent behavior. This proves that even partial or noisy traces can be leveraged for key recovery when combined with machine learning._

-  **Deep learning–based side-channel attacks using MLP architecture on simulated traces** 
  _The Deep Learning module generates high-resolution traces and trains neural networks to extract secrets from side-channel leakage. This demonstrates how modern deep learning can outperform traditional statistical methods in cryptographic key recovery._


---

## Project Structure

- `bip32/`: Timing and glitch attacks on hardened derivation
- `ecdsa/`: Nonce collision and private key recovery
- `blind_signing/`: Attacks and countermeasures (classic + ZKP)
- `fault_attacks_ml/`: Machine Learning-based fault recovery
- `sca_attacks_dl/`: Deep Learning-based side-channel attacks

Each module is fully commented.

---

## Reproducibility & Code Quality

-  Formatted with `cargo fmt` 
-  Audited with `cargo clippy`
-  Includes **unit tests** for critical modules to ensure correctness and reproducibility 
-  Contains a centralized `main()` function to orchestrate attacks, generate traces 
-  Machine Learning via `smartcore` 
-  ZKP via zkSNARKs 
-  Fully commented and documented for clarity 

---

## Getting Started

```bash
# Clone and build
git clone https://github.com/tamannbatchi/attacks-suite.git
cd attacks-project
cargo build --release

# Run main orchestrator
cargo run

# Run unit tests
cargo test
