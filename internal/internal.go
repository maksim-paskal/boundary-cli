/*
Copyright paskal.maksim@gmail.com
Licensed under the Apache License, Version 2.0 (the "License")
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/maksim-paskal/boundary-cli/pkg/utils"

	"github.com/briandowns/spinner"
	"github.com/manifoldco/promptui"
	"github.com/pkg/errors"
)

func NewApplication() *Application {
	return &Application{
		BoundaryBin:   "boundary",
		BoundaryToken: "~/.boundary_token",
	}
}

type Application struct {
	BoundaryBin   string
	BoundaryToken string
}

func (a *Application) startSpinner(loadingTarget string) *spinner.Spinner {
	s := spinner.New(spinner.CharSets[7], 100*time.Millisecond)
	s.Suffix = fmt.Sprintf(" Loading %s...\n", loadingTarget)
	_ = s.Color("green")
	s.Start()

	return s
}

type connectInput struct {
	Target *BoundaryTarget
	Host   *BoundaryHost
	Port   string
}

type BoundaryVersion struct {
	Version string `json:"version"`
}

func (a *Application) version(ctx context.Context) (*BoundaryVersion, error) {
	spinner := a.startSpinner("Boundary version")
	defer spinner.Stop()

	raw, err := a.exec(ctx, "-v")
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute version")
	}

	version := &BoundaryVersion{}
	if err := json.Unmarshal(raw.Bytes(), version); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal version")
	}

	slog.Debug("Boundary version", "version", version.Version)

	return version, nil
}

func (a *Application) connect(ctx context.Context, input *connectInput) error {
	opts := &callOptions{
		LogStdoutStderr: true,
		JSONFormat:      false,
	}

	_, err := a.execOpt(ctx, opts,
		"connect",
		"-target-id="+input.Target.ID,
		"-host-id="+input.Host.ID,
		"-listen-port="+input.Port,
		a.getTokenArg())
	if err != nil {
		return errors.Wrap(err, "failed to connect")
	}

	return nil
}

func (a *Application) auth(ctx context.Context) error {
	type boundaryAuth struct {
		StatusCode int `json:"status_code"`
		Item       struct {
			Attributes struct {
				Token string `json:"token"`
			} `json:"attributes"`
		} `json:"item"`
	}

	result, err := a.exec(ctx, "authenticate", "oidc", "-keyring-type=none")
	if err != nil {
		return errors.Wrap(err, "failed to authenticate")
	}

	boundaryAuthResult := &boundaryAuth{}
	if err := json.Unmarshal(result.Bytes(), boundaryAuthResult); err != nil {
		return errors.Wrap(err, "failed to unmarshal authentication result")
	}

	if boundaryAuthResult.StatusCode != 200 {
		return errors.Errorf("failed to authenticate, status code: %d", boundaryAuthResult.StatusCode)
	}

	slog.Debug("Authenticated successfully", "result", result.String())

	token := []byte(boundaryAuthResult.Item.Attributes.Token)

	if err := os.WriteFile(a.BoundaryToken, token, 0644); err != nil {
		return errors.Wrap(err, "failed to write token to file")
	}

	return nil
}

func (a *Application) exec(ctx context.Context, args ...string) (*bytes.Buffer, error) {
	return a.execOpt(ctx,
		&callOptions{
			JSONFormat: true,
		},
		args...)
}

type callOptions struct {
	LogStdoutStderr bool
	JSONFormat      bool
}

func (a *Application) execOpt(ctx context.Context, opts *callOptions, args ...string) (*bytes.Buffer, error) {
	cmd := exec.CommandContext(ctx, a.BoundaryBin, args...)
	stdoutBuf := bytes.Buffer{}
	stderrBuf := bytes.Buffer{}

	cmd.Env = os.Environ()
	if opts != nil && opts.JSONFormat {
		cmd.Env = append(cmd.Env, "BOUNDARY_CLI_FORMAT=json")
	}
	cmd.Env = append(cmd.Env, "BOUNDARY_TOKEN_FILE="+a.BoundaryToken)

	cmd.Stdout = io.MultiWriter(&stdoutBuf, &utils.DebugWriter{})
	cmd.Stderr = io.MultiWriter(&stderrBuf, &utils.DebugWriter{})

	if opts != nil && opts.LogStdoutStderr {
		cmd.Stdout = io.MultiWriter(&stdoutBuf, &utils.DebugWriter{}, os.Stdout)
		cmd.Stderr = io.MultiWriter(&stderrBuf, &utils.DebugWriter{}, os.Stderr)
	}

	slog.Debug("run", "command", cmd.String())

	if err := cmd.Run(); err != nil {
		slog.Debug("Command failed", "error", err.Error(), "stderr", stderrBuf.String())

		if strings.Contains(stderrBuf.String(), "Unauthenticated") {
			if authErr := a.auth(ctx); authErr == nil {
				return a.exec(ctx, args...)
			} else {
				return nil, errors.Wrap(authErr, "failed to authenticate")
			}
		}

		return nil, errors.Wrapf(err, "failed to run command %s", cmd.String())
	}

	return &stdoutBuf, nil
}

type BoundaryTarget struct {
	ID   string
	Name string
}

func (a *Application) getTokenArg() string {
	return "-token=file://" + a.BoundaryToken
}

func (a *Application) getBoundaryTargets(ctx context.Context) ([]BoundaryTarget, error) {
	spinner := a.startSpinner("Boundary targets")
	defer spinner.Stop()

	targetsRaw, err := a.exec(ctx, "targets", "list", a.getTokenArg())
	if err != nil {
		return nil, errors.Wrap(err, "failed to get targets")
	}

	type rawStruct struct {
		StatusCode int `json:"status_code"`
		Items      []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}

	rawResult := &rawStruct{}
	if err := json.Unmarshal(targetsRaw.Bytes(), rawResult); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal targets")
	}

	if rawResult.StatusCode != 200 {
		return nil, errors.Errorf("failed to get targets, status code: %d", rawResult.StatusCode)
	}

	slog.Debug("Targets retrieved successfully", "result", rawResult)

	targets := make([]BoundaryTarget, len(rawResult.Items))
	for i, item := range rawResult.Items {
		targets[i] = BoundaryTarget{
			ID:   item.ID,
			Name: item.Name,
		}
	}

	return targets, nil
}

func (a *Application) askUserForTarget(ctx context.Context) (*BoundaryTarget, error) {
	targets, err := a.getBoundaryTargets(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get targets")
	}

	sort.Slice(targets, func(i, j int) bool {
		return strings.Compare(
			utils.FormatPort(targets[i].Name, 3),
			utils.FormatPort(targets[j].Name, 3),
		) < 0
	})

	targetNames := make([]string, len(targets))
	for i, target := range targets {
		targetNames[i] = target.Name
	}

	promptSelect := promptui.Select{
		Label: "Select target",
		Items: targetNames,
	}

	selected, _, err := promptSelect.Run()
	if err != nil {
		return nil, errors.Wrap(err, "failed to select target")
	}

	return &targets[selected], nil
}

func (a *Application) createTokenFileIfNotExists() error {
	if _, err := os.Stat(a.BoundaryToken); os.IsNotExist(err) {
		if err := os.WriteFile(a.BoundaryToken, []byte(""), 0644); err != nil {
			return errors.Wrap(err, "failed to create token file")
		}
	}

	return nil
}

type BoundaryHost struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (a *Application) getBoundaryHosts(ctx context.Context, hostCatalog *BoundaryHostCatalog) ([]BoundaryHost, error) {
	spinner := a.startSpinner("Boundary hosts")
	defer spinner.Stop()

	targetRaw, err := a.exec(ctx, "hosts", "list", a.getTokenArg(), "-host-catalog-id="+hostCatalog.ID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get target hosts")
	}

	slog.Debug("Hosts retrieved successfully", "result", targetRaw.String())

	type rawStruct struct {
		StatusCode int `json:"status_code"`
		Items      []struct {
			ID         string            `json:"id"`
			Name       string            `json:"name"`
			Attributes map[string]string `json:"attributes"`
		} `json:"items"`
	}

	rawResult := &rawStruct{}
	if err := json.Unmarshal(targetRaw.Bytes(), rawResult); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal hosts")
	}

	if rawResult.StatusCode != 200 {
		return nil, errors.Errorf("failed to get hosts, status code: %d", rawResult.StatusCode)
	}

	slog.Debug("Hosts retrieved successfully", "result", rawResult)

	hosts := make([]BoundaryHost, len(rawResult.Items))
	for i, item := range rawResult.Items {
		hosts[i] = BoundaryHost{
			ID:   item.ID,
			Name: item.Name,
		}
	}

	return hosts, nil
}

type BoundaryHostCatalog struct {
	ID string `json:"id"`
}

func (a *Application) getBoundaryTargetHostCatalog(ctx context.Context, target *BoundaryTarget) ([]BoundaryHostCatalog, error) {
	spinner := a.startSpinner("Boundary target host-catalog")
	defer spinner.Stop()

	targetRaw, err := a.exec(ctx, "targets", "read", a.getTokenArg(), "-id="+target.ID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get target host catalog")
	}

	slog.Debug("Target host catalog retrieved successfully", "result", targetRaw.String())

	type rawStruct struct {
		StatusCode int `json:"status_code"`
		Item       struct {
			HostSources []struct {
				ID            string `json:"id"`
				HostCatalogID string `json:"host_catalog_id"`
			} `json:"host_sources"`
		} `json:"item"`
	}

	rawResult := &rawStruct{}
	if err := json.Unmarshal(targetRaw.Bytes(), rawResult); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal target host catalog")
	}

	if rawResult.StatusCode != 200 {
		return nil, errors.Errorf("failed to get target host catalog, status code: %d", rawResult.StatusCode)
	}

	slog.Debug("Target host catalog retrieved successfully", "result", rawResult)

	hostCatalogs := make([]BoundaryHostCatalog, len(rawResult.Item.HostSources))
	for i, item := range rawResult.Item.HostSources {
		hostCatalogs[i] = BoundaryHostCatalog{
			ID: item.HostCatalogID,
		}
	}

	return hostCatalogs, nil
}

func (a *Application) askUserForHost(ctx context.Context, target *BoundaryTarget) (*BoundaryHost, error) {
	hostCatalogs, err := a.getBoundaryTargetHostCatalog(ctx, target)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get host catalogs")
	}

	slog.Debug("Host catalogs retrieved successfully", "hostCatalogs", hostCatalogs)

	hosts := make([]BoundaryHost, 0)

	for _, hostCatalog := range hostCatalogs {
		hostCatalogHosts, err := a.getBoundaryHosts(ctx, &hostCatalog)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get hosts")
		}

		hosts = append(hosts, hostCatalogHosts...)
	}

	sort.Slice(hosts, func(i, j int) bool {
		return strings.Compare(
			utils.FormatPort(hosts[i].Name, 3),
			utils.FormatPort(hosts[j].Name, 3),
		) < 0
	})

	hostNames := make([]string, len(hosts))
	for i, host := range hosts {
		hostNames[i] = host.Name
	}

	promptSelect := promptui.Select{
		Label: "Select host",
		Items: hostNames,
		Size:  10,
	}

	selected, _, err := promptSelect.Run()
	if err != nil {
		return nil, errors.Wrap(err, "failed to select target")
	}

	return &hosts[selected], nil
}

func (a *Application) askUserForPort(_ context.Context, target *BoundaryTarget, host *BoundaryHost) (string, error) {
	defaultPort := utils.FormatPort(target.Name, 3) + utils.FormatPort(host.Name, 2)

	prompt := promptui.Prompt{
		Label:       "Port",
		AllowEdit:   true,
		Default:     defaultPort,
		HideEntered: true,
		Validate: func(input string) error {
			port, err := strconv.Atoi(input)
			if err != nil {
				return errors.New("Invalid number")
			}

			if port < 1 || port > 65535 {
				return errors.New("Port must be between 1 and 65535")
			}
			return nil
		},
	}

	port, err := prompt.Run()
	if err != nil {
		return "", errors.Wrap(err, "failed to ask user for port")
	}

	return port, nil
}

func (a *Application) Init() error {
	if a.BoundaryBin == "" {
		return errors.New("Boundary binary path is not set")
	}

	if _, err := exec.LookPath(a.BoundaryBin); err != nil {
		return errors.Wrap(err, "Boundary binary not found")
	}

	userHome, err := os.UserHomeDir()
	if err != nil {
		return errors.Wrap(err, "failed to get user config directory")
	}

	a.BoundaryToken = strings.ReplaceAll(a.BoundaryToken, "~", userHome)

	if err := a.createTokenFileIfNotExists(); err != nil {
		return errors.Wrap(err, "failed to create token file")
	}

	return nil
}

func (a *Application) Run(ctx context.Context) error {
	boundaryVersion, err := a.version(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get version")
	}

	fmt.Printf("Boundary CLI version: %s\n", boundaryVersion.Version)

	target, err := a.askUserForTarget(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to ask user for target")
	}

	slog.Debug("Selected target", "target", target)

	host, err := a.askUserForHost(ctx, target)
	if err != nil {
		return errors.Wrap(err, "failed to ask user for host")
	}

	port, err := a.askUserForPort(ctx, target, host)
	if err != nil {
		return errors.Wrap(err, "failed to ask user for port")
	}

	input := &connectInput{
		Target: target,
		Host:   host,
		Port:   port,
	}

	if err := a.connect(ctx, input); err != nil {
		return errors.Wrap(err, "failed to connect")
	}

	return nil
}
