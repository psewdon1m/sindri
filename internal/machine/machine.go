package machine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"sindri/internal/core"
)

func Handle(ctx context.Context, in io.Reader, out io.Writer, registry *core.Registry, env core.Environment) int {
	dec := json.NewDecoder(in)
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var req core.Request
	if err := dec.Decode(&req); err != nil {
		write(out, core.Result{
			ProtocolVersion: env.ProtocolVersion,
			Status:          core.StatusFailed,
			Error:           &core.ErrorInfo{Code: "INVALID_JSON", Message: err.Error()},
			ExitCode:        core.ExitInvalidCommand,
		})
		return core.ExitInvalidCommand
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); err != io.EOF {
		message := "Only one JSON request is allowed"
		if err != nil {
			message = err.Error()
		}
		write(out, core.Result{
			ProtocolVersion: env.ProtocolVersion,
			RequestID:       req.RequestID,
			Status:          core.StatusFailed,
			Action:          req.Action,
			Error:           &core.ErrorInfo{Code: "INVALID_JSON", Message: message},
			ExitCode:        core.ExitInvalidCommand,
		})
		return core.ExitInvalidCommand
	}
	if len(req.RequestID) > 128 {
		res := core.Result{
			ProtocolVersion: env.ProtocolVersion,
			RequestID:       req.RequestID,
			Status:          core.StatusFailed,
			Action:          req.Action,
			Error:           &core.ErrorInfo{Code: "INVALID_REQUEST_ID", Message: "request_id must not exceed 128 characters"},
			ExitCode:        core.ExitInvalidCommand,
		}
		write(out, res)
		return res.ExitCode
	}
	if req.ProtocolVersion != "" && req.ProtocolVersion != env.ProtocolVersion {
		res := core.Result{
			ProtocolVersion: env.ProtocolVersion,
			RequestID:       req.RequestID,
			Status:          core.StatusFailed,
			Action:          req.Action,
			Error:           &core.ErrorInfo{Code: "UNSUPPORTED_PROTOCOL", Message: "Unsupported protocol version"},
			ExitCode:        core.ExitInvalidCommand,
		}
		write(out, res)
		return res.ExitCode
	}
	req.Source = "machine"
	res := core.Execute(ctx, registry, env, req)
	write(out, res)
	return res.ExitCode
}

func write(out io.Writer, result core.Result) {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(out, `{"status":"failed","error":{"code":"ENCODE_FAILED","message":%q}}`+"\n", err.Error())
	}
}
