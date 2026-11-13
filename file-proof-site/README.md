# File Proof (preview)

A small, local-first browser utility built alongside Lumen SDK.

## What it does

- Calculates a SHA-256 fingerprint for a selected local file.
- Saves a JSON receipt containing the fingerprint and basic file metadata.
- Later compares a selected file against that receipt.
- Reads the file in the browser; this page has no upload code, account system, analytics, or external API calls.

## Use

1. Open the HTTPS page in a current browser.
2. Choose a file and select **Generate fingerprint**.
3. Save the JSON receipt somewhere separate from the original file.
4. To check a later copy, select the receipt and the file, then select **Verify against receipt**.

## Scope and limitations

A matching SHA-256 fingerprint is strong evidence that the file bytes match the recorded fingerprint. It does not establish who created a file, whether the original content is truthful, when it was originally created, or whether the receipt is authentic. It is not a digital signature, chain-of-custody system, forensic certification, backup service, or compliance product.

The first preview limits files to 100 MiB because the browser calculates SHA-256 over the selected file in memory. Keep JSON receipts private if their filenames or metadata are sensitive.

## Privacy

The page has no external dependencies and no network request code. The file is read locally by the browser and is not uploaded. The hosting provider will still receive ordinary web requests for the page itself.

## Status

Preview build. It has not yet completed independent browser/device testing or a formal security review. Do not rely on it as the sole evidence in legal, forensic, medical, financial, or safety-critical matters.
