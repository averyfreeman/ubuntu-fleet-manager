package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/systeminfo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMain(m *testing.M) {
	if os.Getenv("UFM_TEST_STDIO_CHILD") == "1" {
		collector := systeminfo.Collect
		if os.Getenv("UFM_TEST_SYSTEM_INFO_ERROR") == "1" {
			collector = func() (systeminfo.Info, error) {
				return systeminfo.Info{}, errors.New("system information unavailable")
			}
		}
		if err := runStdioWithCollector(context.Background(), collector); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStdioSystemInfoContract(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session := connectStdio(t, ctx, false)
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "get_system_info" {
		t.Fatalf("tools = %v, want only get_system_info", toolNames(tools.Tools))
	}
	annotations := tools.Tools[0].Annotations
	if annotations == nil || !annotations.ReadOnlyHint || !annotations.IdempotentHint || annotations.OpenWorldHint == nil || *annotations.OpenWorldHint {
		t.Errorf("get_system_info annotations = %#v, want read-only, idempotent, and closed-world", annotations)
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_system_info",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("call get_system_info: %v", err)
	}
	if result.IsError {
		t.Fatalf("get_system_info returned an MCP tool error: %v", result.Content)
	}

	payload, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured result: %v", err)
	}
	var info map[string]any
	if err := json.Unmarshal(payload, &info); err != nil {
		t.Fatalf("decode structured result: %v", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	if info["hostname"] != hostname {
		t.Errorf("hostname = %v, want %q", info["hostname"], hostname)
	}
	if info["architecture"] != runtime.GOARCH {
		t.Errorf("architecture = %v, want %q", info["architecture"], runtime.GOARCH)
	}
	osInfo, ok := info["os"].(map[string]any)
	if !ok {
		t.Errorf("os = %T, want an object", info["os"])
	} else {
		if id, ok := osInfo["id"].(string); !ok || id == "" {
			t.Errorf("os.id = %v, want a non-empty string", osInfo["id"])
		}
		if prettyName, ok := osInfo["pretty_name"].(string); !ok || prettyName == "" {
			t.Errorf("os.pretty_name = %v, want a non-empty string", osInfo["pretty_name"])
		}
		if versionID, ok := osInfo["version_id"].(string); !ok || versionID == "" {
			t.Errorf("os.version_id = %v, want a non-empty string", osInfo["version_id"])
		}
		assertAllowedKeys(t, "os", osInfo, []string{"id", "pretty_name", "version_id", "version_codename"})
	}
	kernel, ok := info["kernel"].(map[string]any)
	if !ok {
		t.Errorf("kernel = %T, want an object", info["kernel"])
	} else {
		for _, key := range []string{"name", "release"} {
			if value, ok := kernel[key].(string); !ok || value == "" {
				t.Errorf("kernel.%s = %v, want a non-empty string", key, kernel[key])
			}
		}
		assertAllowedKeys(t, "kernel", kernel, []string{"name", "release"})
	}
	memory, ok := info["memory"].(map[string]any)
	if !ok {
		t.Fatalf("memory = %T, want an object", info["memory"])
	}
	if total, ok := memory["total_bytes"].(float64); !ok || total <= 0 {
		t.Errorf("memory.total_bytes = %v, want a positive number", memory["total_bytes"])
	}
	if available, ok := memory["available_bytes"].(float64); !ok || available <= 0 {
		t.Errorf("memory.available_bytes = %v, want a positive number", memory["available_bytes"])
	}
	assertAllowedKeys(t, "memory", memory, []string{"total_bytes", "available_bytes"})
	root, ok := info["root_filesystem"].(map[string]any)
	if !ok {
		t.Fatalf("root_filesystem = %T, want an object", info["root_filesystem"])
	}
	if total, ok := root["total_bytes"].(float64); !ok || total <= 0 {
		t.Errorf("root_filesystem.total_bytes = %v, want a positive number", root["total_bytes"])
	}
	for _, key := range []string{"used_bytes", "free_bytes", "available_bytes"} {
		if value, ok := root[key].(float64); !ok || value < 0 {
			t.Errorf("root_filesystem.%s = %v, want a non-negative number", key, root[key])
		}
	}
	assertAllowedKeys(t, "root_filesystem", root, []string{"total_bytes", "used_bytes", "free_bytes", "available_bytes"})
	assertAllowedKeys(t, "result", info, []string{"os", "hostname", "kernel", "architecture", "memory", "root_filesystem", "collected_at"})
	if collectedAt, ok := info["collected_at"].(string); !ok || collectedAt == "" {
		t.Errorf("collected_at = %v, want an RFC3339 timestamp", info["collected_at"])
	} else if _, err := time.Parse(time.RFC3339Nano, collectedAt); err != nil {
		t.Errorf("collected_at = %q, want an RFC3339 timestamp: %v", collectedAt, err)
	}
}

func TestStdioRejectsUnexpectedArgument(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session := connectStdio(t, ctx, false)
	defer session.Close()

	result, callErr := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_system_info",
		Arguments: map[string]any{"unexpected": true},
	})
	if callErr == nil && !result.IsError {
		t.Fatalf("unexpected argument was accepted: %#v", result.StructuredContent)
	}
	if _, err := session.ListTools(ctx, nil); err != nil {
		t.Fatalf("server was unavailable after rejecting unexpected input (call error: %v): %v", callErr, err)
	}
}

func TestStdioReportsCollectionFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session := connectStdio(t, ctx, true)
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_system_info",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("call get_system_info: %v", err)
	}
	if !result.IsError {
		t.Fatal("collection failure was not returned as a tool error")
	}
	if len(result.Content) == 0 {
		t.Fatal("collection failure returned no explanatory content")
	}
	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok || textContent.Text == "" {
		t.Fatalf("collection failure content = %#v, want explanatory text", result.Content[0])
	}
	if !strings.Contains(textContent.Text, "system information unavailable") {
		t.Errorf("collection failure content = %q, want the collection error", textContent.Text)
	}
}

func connectStdio(t *testing.T, ctx context.Context, failCollection bool) *mcp.ClientSession {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestStdioChild$")
	env := append(os.Environ(), "UFM_TEST_STDIO_CHILD=1")
	if failCollection {
		env = append(env, "UFM_TEST_SYSTEM_INFO_ERROR=1")
	}
	cmd.Env = env
	client := mcp.NewClient(&mcp.Implementation{Name: "contract-test", Version: "test"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect to stdio MCP server: %v", err)
	}
	return session
}

func TestStdioChild(t *testing.T) {}

func toolNames(tools []*mcp.Tool) []string {
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	return names
}

func assertAllowedKeys(t *testing.T, objectName string, object map[string]any, allowed []string) {
	t.Helper()
	allowedSet := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = true
	}
	for key := range object {
		if !allowedSet[key] {
			t.Errorf("%s contains undocumented field %q", objectName, key)
		}
	}
}
