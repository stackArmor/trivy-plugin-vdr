package registry

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// DockerConfig is the subset of Docker's config.json that Trivy reads for
// registry credentials.
type DockerConfig struct {
	Auths map[string]DockerAuth `json:"auths"`
}

// DockerAuth is a single registry credential entry. Auth is the base64 of
// "username:password" and is what Trivy's keychain reads first.
type DockerAuth struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Auth     string `json:"auth"`
}

// newAuth builds a DockerAuth with the Auth field populated from username/password.
func newAuth(username, password string) DockerAuth {
	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return DockerAuth{Username: username, Password: password, Auth: encoded}
}

// normalizeHost strips scheme and Docker Hub's legacy registry path so secret
// keys line up with the host produced by reference.Domain.
func normalizeHost(key string) string {
	host := key
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	// Drop any path component (e.g. index.docker.io/v1/).
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if host == "index.docker.io" || host == "registry-1.docker.io" {
		return "docker.io"
	}
	return host
}

// normalizeAuth ensures the Auth field is populated; if only username/password
// are present it computes it, and if only Auth is present it decodes the pair.
func normalizeAuth(a DockerAuth) DockerAuth {
	if a.Auth == "" && (a.Username != "" || a.Password != "") {
		return newAuth(a.Username, a.Password)
	}
	if a.Auth != "" && a.Username == "" && a.Password == "" {
		if decoded, err := base64.StdEncoding.DecodeString(a.Auth); err == nil {
			if user, pass, ok := strings.Cut(string(decoded), ":"); ok {
				a.Username, a.Password = user, pass
			}
		}
	}
	return a
}

// ParseDockerConfigJSON parses the body of a kubernetes.io/dockerconfigjson
// Secret (the ".dockerconfigjson" data key) into host -> DockerAuth.
func ParseDockerConfigJSON(data []byte) (map[string]DockerAuth, error) {
	var cfg DockerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse dockerconfigjson: %w", err)
	}
	return normalizeAuths(cfg.Auths), nil
}

// ParseDockerCfg parses the legacy kubernetes.io/dockercfg Secret body (the
// ".dockercfg" data key), which is the auths map without the top-level wrapper.
func ParseDockerCfg(data []byte) (map[string]DockerAuth, error) {
	var auths map[string]DockerAuth
	if err := json.Unmarshal(data, &auths); err != nil {
		return nil, fmt.Errorf("parse dockercfg: %w", err)
	}
	return normalizeAuths(auths), nil
}

func normalizeAuths(in map[string]DockerAuth) map[string]DockerAuth {
	out := make(map[string]DockerAuth, len(in))
	for key, auth := range in {
		out[normalizeHost(key)] = normalizeAuth(auth)
	}
	return out
}
