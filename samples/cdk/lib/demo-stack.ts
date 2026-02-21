import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';

export class DemoStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // S3 bucket with public read and no encryption - security risks for scanner to find
    const bucket = new s3.Bucket(this, 'PublicBucket', {
      bucketName: 'my-public-demo-bucket',
      publicReadAccess: true,
      encryption: s3.BucketEncryption.UNENCRYPTED,
    });

    // Lambda with no encryption and broad permissions
    const fn = new lambda.Function(this, 'DemoFunction', {
      runtime: lambda.Runtime.NODEJS_18_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = () => {}'),
      environment: {
        BUCKET_NAME: bucket.bucketName,
      },
    });
    bucket.grantReadWrite(fn);
  }
}
