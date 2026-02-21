# CDK sample app

Minimal AWS CDK (TypeScript) app used to test the IaC scanner. It intentionally includes issues the scanner can report:

- **S3**: `publicReadAccess: true`, `encryption: UNENCRYPTED`
- **Lambda**: broad S3 read/write grant

## Layout

- `index.ts` – app entry, instantiates the stack
- `lib/demo-stack.ts` – stack with S3 bucket and Lambda

## Run the scanner

From the repo root (with API key set for analysis/fix):

```bash
# Full scan (analysis + fix, writes report and fixed code to out-cdk/)
iac-scan scan samples/cdk -o ./out-cdk

# Scan only (no AI), to confirm files are picked up
iac-scan scan samples/cdk -o ./out-cdk --scan-only
```

## Run the CDK app (optional)

```bash
cd samples/cdk
npm install
npx cdk synth
```
