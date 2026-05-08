# X3DH Handshake Protocol

X3DH (Extended Triple Diffie-Hellman) is a key agreement protocol for asynchronous secure messaging. It allows Alice to establish a shared secret with Bob even when Bob is offline, by using Bob's published prekey bundle.

Reference:

- Signal X3DH specification: https://signal.org/docs/specifications/x3dh/
- Relevant sections:
  - Section 2.2: KDF definition
  - Section 3.3: Alice's steps
  - Section 3.4: Bob's steps

## Roles And Keys

Bob publishes a prekey bundle containing:

- `IK_B.Public`: Bob's long-term identity public key
- `SPK_B.Public`: Bob's signed prekey public key
- `Sig_B = Sign(Encode(SPK_B.Public), IK_B.Private)`: signature on the signed prekey
- optionally `OPK_B_k.Public`: a one-time prekey public key

Key roles:

- `IK_B`: long-term identity key pair
- `SPK_B`: semi-static signed prekey pair, rotated periodically
- `OPK_B_k`: optional one-time prekey pair, consumed after use
- `EK_A`: Alice's freshly generated ephemeral key pair

## Alice's Steps

Alice fetches Bob's prekey bundle:

```text
{ IK_B.Public, SPK_B.Public, Sig_B, optional OPK_B_k.Public }
```

Alice then:

1. Verifies Bob's signed prekey:

   ```text
   Verify(Sig_B, Encode(SPK_B.Public), IK_B.Public)
   ```

2. Generates an ephemeral key pair `EK_A`.

3. Computes Diffie-Hellman values:

   ```text
   DH1 = DH(IK_A.Private, SPK_B.Public)
   DH2 = DH(EK_A.Private, IK_B.Public)
   DH3 = DH(EK_A.Private, SPK_B.Public)
   DH4 = DH(EK_A.Private, OPK_B_k.Public)   optional
   ```

4. Assembles key material:

   ```text
   KM = DH1 || DH2 || DH3 || (DH4 if present)
   ```

5. Derives the shared secret:

   ```text
   SK = HKDF(
          salt = 0^32,
          IKM  = F || KM,
          info = application-specific context
        )
   ```

   For X25519:

   ```text
   F = 0xFF repeated 32 times
   ```

6. Computes associated data:

   ```text
   AD = Encode(IK_A.Public) || Encode(IK_B.Public)
   ```

7. Encrypts the initial payload using `SK` and `AD`.

8. Sends Bob an initial message containing:

   ```text
   M = (
         IK_A.Public,
         EK_A.Public,
         signed prekey identifier,
         optional one-time prekey identifier,
         ciphertext
       )
   ```

## Bob's Steps

When Bob receives `M`, he:

1. Loads the referenced local keys:

   - `IK_B.Private`
   - `SPK_B.Private`
   - optionally `OPK_B_k.Private`

2. Recomputes associated data:

   ```text
   AD = Encode(IK_A.Public) || Encode(IK_B.Public)
   ```

3. Computes matching Diffie-Hellman values:

   ```text
   DH1 = DH(SPK_B.Private, IK_A.Public)
   DH2 = DH(IK_B.Private, EK_A.Public)
   DH3 = DH(SPK_B.Private, EK_A.Public)
   DH4 = DH(OPK_B_k.Private, EK_A.Public)   optional
   ```

4. Reassembles key material:

   ```text
   KM = DH1 || DH2 || DH3 || (DH4 if used)
   ```

5. Re-derives the same shared secret:

   ```text
   SK = HKDF(
          salt = 0^32,
          IKM  = F || KM,
          info = application-specific context
        )
   ```

6. Decrypts and authenticates the ciphertext using `SK` and `AD`.

7. If a one-time prekey was used, deletes `OPK_B_k` after successful processing.

At the end of the handshake, Alice and Bob share the same symmetric secret `SK`.

## Core X3DH Data Flow

```text
Bob publishes:
  IK_B.Public, SPK_B.Public, Sig_B, optional OPK_B_k.Public

Alice computes:
  DH1, DH2, DH3, optional DH4
  KM = DH1 || DH2 || DH3 || optional DH4
  SK = HKDF(0^32, F || KM, info)
  AD = Encode(IK_A.Public) || Encode(IK_B.Public)

Bob computes:
  matching DH1, DH2, DH3, optional DH4
  same KM
  same SK
  same AD
```

## Security Intuition

The four DH values serve different roles:

- `DH1`: binds Alice's identity key to Bob's signed prekey
- `DH2`: binds Alice's ephemeral key to Bob's identity key
- `DH3`: binds Alice's ephemeral key to Bob's signed prekey
- `DH4`: adds one-time prekey contribution for stronger forward secrecy when available

The associated data binds the session to the parties' identity keys:

```text
AD = Encode(IK_A.Public) || Encode(IK_B.Public)
```

The KDF binds the final secret to the X3DH transcript:

```text
SK = HKDF(0^32, F || KM, info)
```

## Summary

X3DH lets Alice establish a shared secret with Bob asynchronously by using:

- Bob's long-term identity key
- Bob's signed prekey
- optionally Bob's one-time prekey
- Alice's long-term identity key
- Alice's fresh ephemeral key

Both sides derive the same session secret from the same ordered DH transcript, and can then use that secret to bootstrap a secure messaging session.

## The Python Demo

`X3DH_Handshake.py` is a Python demo/prototype of the X3DH-style handshake flow.

Create a virtual environment and install the required package:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
```

Run the demo:

```bash
python X3DH_Handshake.py
```
