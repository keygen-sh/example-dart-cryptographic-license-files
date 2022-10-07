# Example Dart Cryptographic License Files

This is an example of how to verify and decrypt [cryptographic license files](https://keygen.sh/docs/api/cryptography/#cryptographic-lic)
in Dart, using Ed25519 signature verification and AES-256-GCM encryption.

This example verifies the `aes-256-gcm+ed25519` algorithm.

## Running the example

Install dependencies with [`dart pub`](https://dart.dev/tools/pub/cmd):

```bash
dart pub get
```

Then run the example program, where `-f` is the path to a license file,
`-p` is your Ed25519 public key, and `-k` is a license key. Feel free
to use these example values:

```bash
dart run main.dart --license-file examples/license.lic \
  --license-key "9FB017-8E74A0-AC60C5-2C8BF6-2D2B90-V3" \
  --public-key "e8601e48b69383ba520245fd07971e983d06d22c4257cfd82304601479cee788"
```

You should see output indicating that the license file is valid, with its
decrypted dataset:

```
license file was successfully verified!
  > {
      enc: F7g/36/UVMXnPCO7YGA6LaInutjxF06sU...fJCfqFqd5FiLYF33bR1qnYd2M9dfzM+XQ==.Jsw6jutQje0ZWmTn.n++MX8kfMTsqTZQjb2EFVg==,
      sig: VIOP81jRI4EHR7SY69k1O9AV79DNdYgU6uuiY6pR5o9z9Kgh6xli2eHYLVJCprhj2DIPnORD1xxsG22TqeXFDQ==,
      alg: aes-256-gcm+ed25519
    }
license file was successfully decrypted!
  > {
      data: {
        id: e2da9594-218f-41b6-a4d8-43c92b71a6c4,
        type: licenses,
        attributes: {name: Dart Example, ...},
        relationships: {...},
        links: {...}
      }
      included: [
        {id: a963360d-fafb-406a-bfe6-950bafc8bc00, type: products, ...},
        {id: f28621f6-34ec-42e7-84b5-2c659870399b, type: policies, ...},
        {id: 893201f7-e0f8-4a5a-99b5-c567e73f1366, type: users, ...},
        {id: c9e7a95c-e2ac-4580-b3d0-954b48b5c984, type: entitlements, ...},
        {id: dfb1cfce-8614-4ac7-82c4-f5eaa334ba96, type: entitlements, ...},
        {id: ecc6211a-f806-442f-b08a-aa2432d5837a, type: entitlements, ...}
      ],
      meta: {
        issued: 2022-10-04T21:34:54.589Z,
        expiry: 2023-10-04T21:34:54.589Z,
        ttl: 31556952
      }
    }
```

If the verification fails, check your public key.

If the decryption fails, check your license key.

## Questions?

Reach out at [support@keygen.sh](mailto:support@keygen.sh) if you have any
questions or concerns!
