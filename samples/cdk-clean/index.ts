#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { CleanStack } from './lib/clean-stack';

const app = new cdk.App();
new CleanStack(app, 'CleanStack', {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },
});
