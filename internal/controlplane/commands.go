package controlplane

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/hostops"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/mcpserver"
)

func (s *Service) executeHostCommand(ctx context.Context, input mcpserver.HostCommandInput) (mcpserver.HostCommandResult, error) {
	if !s.config.AllowCommandExecution {
		return mcpserver.HostCommandResult{}, fmt.Errorf("host command execution is disabled by the control-plane policy")
	}
	request := hostops.CommandInput{
		Executable: input.Executable, Arguments: input.Arguments,
		WorkingDirectory: input.WorkingDirectory,
	}
	target, encoded, err := s.runHostOperation(ctx, input.HostID, hostops.OperationExecuteCommand, request)
	if err != nil {
		return mcpserver.HostCommandResult{}, err
	}
	var result hostops.CommandResult
	if err := json.Unmarshal(encoded, &result); err != nil {
		return mcpserver.HostCommandResult{}, fmt.Errorf("host agent returned an invalid command result")
	}
	return mcpserver.HostCommandResult{
		HostID: target.HostID, Hostname: target.Hostname, RequestedAt: target.RequestedAt,
		ExitCode: result.ExitCode, Stdout: result.Stdout, Stderr: result.Stderr,
		OutputTruncated: result.OutputTruncated,
	}, nil
}
