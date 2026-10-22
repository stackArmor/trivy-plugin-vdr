// Package awsconfig is the single source of AWS credentials for the plugin, so
// --aws-profile and --aws-role-arn mean the same thing for every AWS call.
//
// Base credentials come from the SDK default chain: environment variables, the
// shared config profile (--aws-profile, else AWS_PROFILE), web identity,
// container credentials (CodeBuild, ECS) and finally EC2 instance metadata.
// When a role is given it is assumed once from those base credentials and
// used for every client, matching how a pipeline assumes a cross-account role
// and then runs everything as that role.
package awsconfig

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// RoleSessionName identifies the plugin's sessions in CloudTrail.
const RoleSessionName = "vdr"

// Load returns an AWS config for region using profile (optional) as the base
// credentials and, when roleARN is set, the assumed role on top of them.
func Load(ctx context.Context, region, profile, roleARN string) (aws.Config, error) {
	options := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if profile != "" {
		options = append(options, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS config for %s: %w", region, err)
	}
	if roleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), roleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = RoleSessionName
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}
	return cfg, nil
}

// CLIEnvironment returns the environment the aws CLI needs to use the same
// base profile as the SDK clients.
func CLIEnvironment(profile string) []string {
	if profile == "" {
		return nil
	}
	return []string{"AWS_PROFILE=" + profile}
}
