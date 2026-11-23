# Artifact Appendix

Paper title: **Invisible Traces: Subversion Attacks on Batch-Issued Credentials**

Requested Badge(s):
  - [x] **Available**
  - [ ] **Functional**
  - [ ] **Reproduced**

## Description

This is a proof of concept for the PETS 2027 paper **Invisible Traces: Subversion Attacks on Batch-Issued Credentials** co-authored by Anna-Birgitta Burmeister, Anna Fennig, Andreas Franke, Karla Friedrichs, Anja Lehmann, Kurt-Kester Leißering, Konrad Letz, and Cavit Özbay. The full paper is available on [ePrint](https://eprint.iacr.org/2026/1229).

The proof of concept implements the four attacks described by the above work, which target the privacy of the users of the European Digital Identity (EUDI) wallet. Each of the attacks demonstrates that undetectable changes to the issuance of credentials make users traceable, i.e. when users employ a credential for authentication, they can be deanonymized. While the paper proves formally the effectiveness of our attacks, this implementation showcases their simplicity.

This demo is built as a modification to the [reference implementation](https://github.com/openwallet-foundation-labs/sd-jwt-python/) of the [IETF SD-JWT specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) written in Python.

### Security/Privacy Issues and Ethical Concerns

The demo is self-contained: it generates toy credentials with or without hidden tracing data, creates a presentation of such a credential and, finally, verifies the presentation to extract embedded tracing data. Thus, there are no security or privacy risks to the machine running the demo.

*Ethics*: This work treats the topic of mass surveillance enabled by digital identity systems. We lay open the possibilities of tracing the use of personal credentials with the goal of raising awareness and educating citizens about the risks of the first EUDI version and, in general, solutions based on batch-issued, salted-hash-based credentials.
By no means is this a ``tutorial'' for malicious issuers to enable tracing; since the presented attacks build on established techniques, we believe that the same results could have been reproduced by a resourceful issuing party. So instead of letting our privacy depend on the fact that no malicious party discovers any tracing method, we deem it more valuable to clearly and publicly describe how the current system is fundamentally vulnerable to subversion and tracking attacks, and that this can only be fixed by changing the issuance mechanism.

## Environment

### Accessibility

The demo is available at: https://github.com/abc013/sd-jwt-python/tree/main

The README contains simple step-by-step instructions to run a demo of each attack.
For simplicity, these instructions employ the `quickstart.py` script, which harnesses the modified EUDI reference implementation to create a subverted credential, present the credential, and extract tracing data via three simple commands and with verbose output to the terminal.

## Notes on Reusability

Beyond the `quickstart.py` script, which offers a high-level proof of concept, the modified wallet code can also be used independently. The modifications enabling the four tracing attacks are mostly in `src/issuer.py` and `src/verifier.py`: the former is extended with the options to embed tracing data into issued credentials via a salt, order, decoy, or ECDSA subversion attack. The latter is extended with the option to extract the tracing data accordingly. Honest issuance and verification is left unchanged.