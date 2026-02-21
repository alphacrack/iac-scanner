#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { DemoStack } from './lib/demo-stack';

const app = new cdk.App();
new DemoStack(app, 'DemoStack', {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },
});
