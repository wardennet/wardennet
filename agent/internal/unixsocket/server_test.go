// Package unixsocket - server_test.go 针对本地 Unix Socket 服务的集成验证。
package unixsocket

import (
	"bufio"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestServer_StartAndDispatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wardennet.sock")
	reg := NewRegistry()
	reg.Register("echo", func(req Request) Response {
		return Response{Ok: true, Data: req.Args}
	})
	reg.Register("status", func(req Request) Response {
		return Response{Ok: true, Data: map[string]interface{}{"ok": "alive"}}
	})

	srv := NewServer(path, reg)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	// 等待 socket 就绪
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// 发送第一个请求
	req1 := Request{Command: "echo", Args: map[string]interface{}{"msg": "hi"}}
	if err := json.NewEncoder(conn).Encode(req1); err != nil {
		t.Fatalf("Encode req1: %v", err)
	}
	resp1, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("Read resp1: %v", err)
	}
	var r1 Response
	if err := json.Unmarshal(resp1, &r1); err != nil {
		t.Fatalf("Unmarshal resp1: %v", err)
	}
	if !r1.Ok {
		t.Errorf("resp1 not ok: %v", r1)
	}

	// 发送第二个请求（同连接）
	req2 := Request{Command: "status"}
	if err := json.NewEncoder(conn).Encode(req2); err != nil {
		t.Fatalf("Encode req2: %v", err)
	}
	resp2, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("Read resp2: %v", err)
	}
	var r2 Response
	if err := json.Unmarshal(resp2, &r2); err != nil {
		t.Fatalf("Unmarshal resp2: %v", err)
	}
	if !r2.Ok {
		t.Errorf("resp2 not ok: %v", r2)
	}
}

func TestServer_UnknownCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wardennet.sock")
	srv := NewServer(path, NewRegistry())
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	req := Request{Command: "nonexistent"}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	respData, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if resp.Ok || resp.Error == "" {
		t.Errorf("expected error response, got %+v", resp)
	}
}
