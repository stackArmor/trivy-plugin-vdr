package ecs

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
)

func TestECSClientHonorsRoleARN(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	client, err := NewAWSClient(context.Background(), ClientOptions{RoleARN: "arn:aws-us-gov:iam::111111111111:role/r"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := client.config(context.Background(), "us-gov-west-1")
	if err != nil {
		t.Fatal(err)
	}
	cache, ok := cfg.Credentials.(*aws.CredentialsCache)
	if !ok || !cache.IsCredentialsProvider(&stscreds.AssumeRoleProvider{}) {
		t.Fatalf("ECS credentials = %T, want the assumed --aws-role-arn role", cfg.Credentials)
	}
}
