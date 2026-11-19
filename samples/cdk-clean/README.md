# CDK clean sample

Minimal AWS CDK (TypeScript) app used to test the IaC scanner:

- **S3**:  private logs bucket, `versioned`, `S3_MANAGED` encryption, `blockPublicAccess: BLOCK_ALL`, `enforceSSL`

## Layout

- `index.ts` – app entry, instantiates the stack
- `lib/clean-stack.ts` – stack with S3 bucket

## Run the scanner

This sample should produce zero findings. Use it to verify the scanner passes clean configurations:

```bash
# Full scan (analysis + fix, writes report and fixed code to out-cdk/)
iac-scan scan samples/cdk-clean -o ./out-cdk

# Scan only (no AI), to confirm files are picked up
iac-scan scan samples/cdk-clean -o ./out-cdk --scan-only
```

## Run the CDK app (optional)

```bash
cd samples/cdk-clean
npm install
npx cdk synth
```
