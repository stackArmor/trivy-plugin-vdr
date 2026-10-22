package swarm

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// SSM truncates command output at 24,000 characters, and `docker service
// inspect` runs to a few KB per service. The collector therefore stages each
// payload on the manager as one gzip+base64 line and reads it back in chunks,
// which needs no S3 bucket and no write access from the customer's instance.
const (
	defaultChunkSize    = 20000
	defaultPollInterval = 2 * time.Second
	defaultTimeout      = 5 * time.Minute
)

// stageScript writes producer's output, gzipped and base64-encoded, to a temp
// file and prints "<length> <path>".
const stageScript = `set -e
f=$(mktemp /tmp/vdr-swarm.XXXXXXXX)
{ %s ; } | gzip -c | base64 | tr -d '\n' > "$f"
printf '%%s %%s' "$(wc -c < "$f" | tr -d ' ')" "$f"`

// servicesProducer emits the {services, networks} document ParseServices
// accepts, so host networking can be resolved.
const servicesProducer = `ids=$(docker service ls -q); printf '{"services":'; if [ -n "$ids" ]; then docker service inspect $ids; else printf '[]'; fi; printf ',"networks":['; docker network ls --no-trunc --format '{{json .}}' | paste -sd, -; printf ']}'`

var stagedPathPattern = regexp.MustCompile(`^/tmp/vdr-swarm\.[A-Za-z0-9]+$`)

// SSMClient is the subset of the SSM API the collector uses.
type SSMClient interface {
	SendCommand(ctx context.Context, in *ssm.SendCommandInput, optFns ...func(*ssm.Options)) (*ssm.SendCommandOutput, error)
	GetCommandInvocation(ctx context.Context, in *ssm.GetCommandInvocationInput, optFns ...func(*ssm.Options)) (*ssm.GetCommandInvocationOutput, error)
}

// EC2Client is the subset of the EC2 API used to find a manager node.
type EC2Client interface {
	DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

// SSMOptions selects the manager node and tunes the transfer.
type SSMOptions struct {
	ManagerTagKey   string
	ManagerTagValue string
	// ConfigName is the Swarm config to read; defaults to FedRAMPConfigName.
	ConfigName   string
	ChunkSize    int
	PollInterval time.Duration
	Timeout      time.Duration
}

// Collected is what the collector read from the manager.
type Collected struct {
	InstanceID string
	// Services is a {services, networks} document for ParseServices.
	Services []byte
	// FedRAMPConfig is `docker config inspect` output for ParseFedRAMPConfig;
	// "[]" when the config does not exist.
	FedRAMPConfig []byte
}

// ParseManagerTag splits "key=value".
func ParseManagerTag(tag string) (string, string, error) {
	key, value, ok := strings.Cut(tag, "=")
	if !ok || strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
		return "", "", fmt.Errorf("manager tag %q must be key=value", tag)
	}
	return strings.TrimSpace(key), strings.TrimSpace(value), nil
}

// CollectViaSSM runs the inventory commands on a running manager node over
// SSM Run Command.
func CollectViaSSM(ctx context.Context, client SSMClient, ec2Client EC2Client, opts SSMOptions) (Collected, error) {
	if opts.ConfigName == "" {
		opts.ConfigName = FedRAMPConfigName
	}
	if opts.ChunkSize <= 0 {
		opts.ChunkSize = defaultChunkSize
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = defaultPollInterval
	}
	instanceID, err := findManager(ctx, ec2Client, opts)
	if err != nil {
		return Collected{}, err
	}
	runner := ssmRunner{client: client, instanceID: instanceID, opts: opts}

	services, err := runner.fetch(ctx, servicesProducer)
	if err != nil {
		return Collected{}, fmt.Errorf("collect swarm services from %s: %w", instanceID, err)
	}
	config, err := runner.fetch(ctx, fmt.Sprintf("docker config inspect %s 2>/dev/null || printf '[]'", opts.ConfigName))
	if err != nil {
		return Collected{}, fmt.Errorf("collect %s config from %s: %w", opts.ConfigName, instanceID, err)
	}
	return Collected{InstanceID: instanceID, Services: services, FedRAMPConfig: config}, nil
}

func findManager(ctx context.Context, client EC2Client, opts SSMOptions) (string, error) {
	out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{Filters: []ec2types.Filter{
		{Name: aws.String("tag:" + opts.ManagerTagKey), Values: []string{opts.ManagerTagValue}},
		{Name: aws.String("instance-state-name"), Values: []string{"running"}},
	}})
	if err != nil {
		return "", fmt.Errorf("find swarm manager: %w", err)
	}
	var ids []string
	for _, reservation := range out.Reservations {
		for _, instance := range reservation.Instances {
			if id := aws.ToString(instance.InstanceId); id != "" {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("no running instance tagged %s=%s; tag a Swarm manager node or pass --services-file", opts.ManagerTagKey, opts.ManagerTagValue)
	}
	sort.Strings(ids)
	return ids[0], nil
}

type ssmRunner struct {
	client     SSMClient
	instanceID string
	opts       SSMOptions
}

// fetch stages producer's output on the manager, reads it back in chunks,
// removes the staged file, and returns the decoded bytes.
func (r ssmRunner) fetch(ctx context.Context, producer string) ([]byte, error) {
	staged, err := r.run(ctx, fmt.Sprintf(stageScript, producer))
	if err != nil {
		return nil, err
	}
	sizeText, path, ok := strings.Cut(strings.TrimSpace(staged), " ")
	size, convErr := strconv.Atoi(sizeText)
	if !ok || convErr != nil || size < 0 {
		return nil, fmt.Errorf("unexpected staging output %q", staged)
	}
	if !stagedPathPattern.MatchString(path) {
		return nil, fmt.Errorf("unexpected staged path %q", path)
	}
	defer func() {
		// Best effort: the payload is inventory metadata, and mktemp is 0600.
		_, _ = r.run(context.WithoutCancel(ctx), "rm -f "+path)
	}()

	var encoded strings.Builder
	for start := 1; start <= size; start += r.opts.ChunkSize {
		end := start + r.opts.ChunkSize - 1
		chunk, err := r.run(ctx, fmt.Sprintf("cut -c %d-%d %s", start, end, path))
		if err != nil {
			return nil, err
		}
		encoded.WriteString(strings.TrimSpace(chunk))
	}
	if encoded.Len() != size {
		return nil, fmt.Errorf("read %d of %d staged bytes", encoded.Len(), size)
	}
	compressed, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		return nil, fmt.Errorf("decode staged output: %w", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("decompress staged output: %w", err)
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// run executes one shell script on the manager and returns its stdout.
func (r ssmRunner) run(ctx context.Context, script string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()
	sent, err := r.client.SendCommand(ctx, &ssm.SendCommandInput{
		DocumentName: aws.String("AWS-RunShellScript"),
		InstanceIds:  []string{r.instanceID},
		Parameters:   map[string][]string{"commands": {script}},
		Comment:      aws.String("trivy-plugin-vdr swarm inventory"),
	})
	if err != nil {
		return "", fmt.Errorf("send command: %w", err)
	}
	commandID := aws.ToString(sent.Command.CommandId)
	for {
		out, err := r.client.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  aws.String(commandID),
			InstanceId: aws.String(r.instanceID),
		})
		var notYet *ssmtypes.InvocationDoesNotExist
		switch {
		case errors.As(err, &notYet):
			// The invocation is not visible until the agent picks it up.
		case err != nil:
			return "", fmt.Errorf("get command invocation: %w", err)
		case out.Status == ssmtypes.CommandInvocationStatusSuccess:
			return aws.ToString(out.StandardOutputContent), nil
		case out.Status == ssmtypes.CommandInvocationStatusFailed,
			out.Status == ssmtypes.CommandInvocationStatusCancelled,
			out.Status == ssmtypes.CommandInvocationStatusTimedOut:
			return "", fmt.Errorf("command %s %s: %s", commandID, strings.ToLower(string(out.Status)), strings.TrimSpace(aws.ToString(out.StandardErrorContent)))
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("command %s: %w", commandID, ctx.Err())
		case <-time.After(r.opts.PollInterval):
		}
	}
}
