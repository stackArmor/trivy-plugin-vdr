package swarm

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type fakeEC2 struct {
	input *ec2.DescribeInstancesInput
	ids   []string
}

func (f *fakeEC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	f.input = in
	var instances []ec2types.Instance
	for _, id := range f.ids {
		instances = append(instances, ec2types.Instance{InstanceId: aws.String(id)})
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: instances}}}, nil
}

// fakeSSM emulates a manager node: staging commands write the gzip+base64
// payload to a temp path, cut commands return slices of it, rm deletes it.
type fakeSSM struct {
	servicesJSON string
	configJSON   string
	files        map[string]string
	commands     []string
	instanceIDs  []string
	results      map[string]string // command ID -> stdout
	failures     map[string]string // command ID -> stderr
	polls        map[string]int
	failOn       string
	stagedPath   string
}

var cutPattern = regexp.MustCompile(`^cut -c (\d+)-(\d+) (\S+)$`)

func gzipBase64(t *testing.T, content string) string {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func (f *fakeSSM) run(t *testing.T, script string) (string, string) {
	if f.failOn != "" && strings.Contains(script, f.failOn) {
		return "", "docker: permission denied"
	}
	switch {
	case strings.Contains(script, "mktemp"):
		payload := f.configJSON
		if strings.Contains(script, "docker service ls") {
			payload = f.servicesJSON
		}
		path := f.stagedPath
		if path == "" {
			path = fmt.Sprintf("/tmp/vdr-swarm.abc%d", len(f.files))
		}
		encoded := gzipBase64(t, payload)
		f.files[path] = encoded
		return fmt.Sprintf("%d %s", len(encoded), path), ""
	case cutPattern.MatchString(script):
		m := cutPattern.FindStringSubmatch(script)
		from, _ := strconv.Atoi(m[1])
		to, _ := strconv.Atoi(m[2])
		content := f.files[m[3]]
		if to > len(content) {
			to = len(content)
		}
		return content[from-1 : to], ""
	case strings.HasPrefix(script, "rm -f "):
		delete(f.files, strings.TrimPrefix(script, "rm -f "))
		return "", ""
	}
	t.Fatalf("unexpected remote script: %s", script)
	return "", ""
}

type fakeSSMClient struct {
	t *testing.T
	*fakeSSM
}

func (c fakeSSMClient) SendCommand(_ context.Context, in *ssm.SendCommandInput, _ ...func(*ssm.Options)) (*ssm.SendCommandOutput, error) {
	if aws.ToString(in.DocumentName) != "AWS-RunShellScript" {
		c.t.Fatalf("document = %s", aws.ToString(in.DocumentName))
	}
	c.instanceIDs = append(c.instanceIDs, in.InstanceIds...)
	script := strings.Join(in.Parameters["commands"], "\n")
	c.commands = append(c.commands, script)
	id := fmt.Sprintf("cmd-%d", len(c.commands))
	stdout, stderr := c.run(c.t, script)
	if stderr != "" {
		c.failures[id] = stderr
	} else {
		c.results[id] = stdout
	}
	return &ssm.SendCommandOutput{Command: &ssmtypes.Command{CommandId: aws.String(id)}}, nil
}

func (c fakeSSMClient) GetCommandInvocation(_ context.Context, in *ssm.GetCommandInvocationInput, _ ...func(*ssm.Options)) (*ssm.GetCommandInvocationOutput, error) {
	id := aws.ToString(in.CommandId)
	c.polls[id]++
	// The invocation is not visible immediately after SendCommand, then runs.
	switch c.polls[id] {
	case 1:
		return nil, &ssmtypes.InvocationDoesNotExist{}
	case 2:
		return &ssm.GetCommandInvocationOutput{Status: ssmtypes.CommandInvocationStatusInProgress}, nil
	}
	if stderr, failed := c.failures[id]; failed {
		return &ssm.GetCommandInvocationOutput{Status: ssmtypes.CommandInvocationStatusFailed, StandardErrorContent: aws.String(stderr)}, nil
	}
	return &ssm.GetCommandInvocationOutput{Status: ssmtypes.CommandInvocationStatusSuccess, StandardOutputContent: aws.String(c.results[id])}, nil
}

func newFakeSSM(t *testing.T, servicesJSON, configJSON string) (fakeSSMClient, *fakeSSM) {
	state := &fakeSSM{
		servicesJSON: servicesJSON,
		configJSON:   configJSON,
		files:        map[string]string{},
		results:      map[string]string{},
		failures:     map[string]string{},
		polls:        map[string]int{},
	}
	return fakeSSMClient{t: t, fakeSSM: state}, state
}

func testSSMOptions() SSMOptions {
	return SSMOptions{ManagerTagKey: "swarm-node-type", ManagerTagValue: "manager", ChunkSize: 64, PollInterval: time.Millisecond}
}

func TestCollectViaSSMPicksRunningManager(t *testing.T) {
	client, state := newFakeSSM(t, "[]", "[]")
	ec2Client := &fakeEC2{ids: []string{"i-0bbb", "i-0aaa"}}
	if _, err := CollectViaSSM(context.Background(), client, ec2Client, testSSMOptions()); err != nil {
		t.Fatalf("CollectViaSSM: %v", err)
	}
	filters := map[string][]string{}
	for _, filter := range ec2Client.input.Filters {
		filters[aws.ToString(filter.Name)] = filter.Values
	}
	if strings.Join(filters["tag:swarm-node-type"], ",") != "manager" || strings.Join(filters["instance-state-name"], ",") != "running" {
		t.Fatalf("filters = %v", filters)
	}
	for _, id := range state.instanceIDs {
		if id != "i-0aaa" {
			t.Fatalf("commands sent to %s, want the first manager by ID (i-0aaa)", id)
		}
	}
}

func TestCollectViaSSMReassemblesChunkedOutput(t *testing.T) {
	// A small chunk size forces several reads, as SSM's 24,000-character
	// output limit does for a real swarm.
	services := `{"services": ` + string(loadFixture(t)) + `, "networks": []}`
	client, state := newFakeSSM(t, services, "[]")
	collected, err := CollectViaSSM(context.Background(), client, &fakeEC2{ids: []string{"i-1"}}, testSSMOptions())
	if err != nil {
		t.Fatalf("CollectViaSSM: %v", err)
	}
	if string(collected.Services) != services {
		t.Fatalf("services were not reassembled exactly")
	}
	cuts := 0
	for _, command := range state.commands {
		if strings.HasPrefix(command, "cut -c ") {
			cuts++
		}
	}
	if cuts < 2 {
		t.Fatalf("cut commands = %d, want several chunks", cuts)
	}
	if len(state.files) != 0 {
		t.Fatalf("staged files left on the manager: %v", state.files)
	}
	if !strings.Contains(state.commands[0], "docker network ls --no-trunc") {
		t.Fatalf("services script must include the network list:\n%s", state.commands[0])
	}
}

func TestCollectViaSSMMissingConfigIsEmptyInspect(t *testing.T) {
	client, _ := newFakeSSM(t, "[]", "[]")
	collected, err := CollectViaSSM(context.Background(), client, &fakeEC2{ids: []string{"i-1"}}, testSSMOptions())
	if err != nil {
		t.Fatalf("CollectViaSSM: %v", err)
	}
	if strings.TrimSpace(string(collected.FedRAMPConfig)) != "[]" {
		t.Fatalf("config = %q, want the empty inspect result", collected.FedRAMPConfig)
	}
	data, _, err := ParseFedRAMPConfig(collected.FedRAMPConfig)
	if err != nil || len(data) != 0 {
		t.Fatalf("data = %v, err = %v", data, err)
	}
}

func TestCollectViaSSMReportsRemoteFailure(t *testing.T) {
	client, state := newFakeSSM(t, "[]", "[]")
	state.failOn = "docker service ls"
	_, err := CollectViaSSM(context.Background(), client, &fakeEC2{ids: []string{"i-1"}}, testSSMOptions())
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v, want the remote stderr", err)
	}
}

func TestCollectViaSSMRejectsUnexpectedStagedPath(t *testing.T) {
	client, state := newFakeSSM(t, "[]", "[]")
	state.stagedPath = "/tmp/x; rm -rf /"
	_, err := CollectViaSSM(context.Background(), client, &fakeEC2{ids: []string{"i-1"}}, testSSMOptions())
	if err == nil || !strings.Contains(err.Error(), "unexpected staged path") {
		t.Fatalf("err = %v", err)
	}
}

func TestCollectViaSSMNoManager(t *testing.T) {
	client, _ := newFakeSSM(t, "[]", "[]")
	_, err := CollectViaSSM(context.Background(), client, &fakeEC2{}, testSSMOptions())
	if err == nil || !strings.Contains(err.Error(), "swarm-node-type=manager") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseManagerTag(t *testing.T) {
	key, value, err := ParseManagerTag("swarm-node-type=manager")
	if err != nil || key != "swarm-node-type" || value != "manager" {
		t.Fatalf("got %q %q %v", key, value, err)
	}
	for _, bad := range []string{"", "manager", "=manager", "swarm-node-type="} {
		if _, _, err := ParseManagerTag(bad); err == nil {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}
