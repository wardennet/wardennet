package main

import (
    "encoding/json"
    "fmt"
    "net"
    "os"
    "time"
)

func main() {
    sockPath := "d:/coder/business/WardenNet/agent_e2e_test/state/wardenet.sock"
    
    conn, err := net.Dial("unix", sockPath)
    if err != nil {
        fmt.Printf("Failed to connect: %v\n", err)
        os.Exit(1)
    }
    defer conn.Close()
    
    conn.SetDeadline(time.Now().Add(3 * time.Second))
    buf := make([]byte, 4096)
    
    // Send blocklist.status to check state
    req := map[string]interface{}{
        "command": "blocklist.status",
        "args": map[string]interface{}{},
    }
    data, _ := json.Marshal(req)
    data = append(data, '\n')
    conn.Write(data)
    n, _ := conn.Read(buf)
    fmt.Printf("Status: %s\n", string(buf[:n]))
    
    // Now send a blocklist.add command to manually add an IP
    req2 := map[string]interface{}{
        "command": "blocklist.add",
        "args": map[string]interface{}{
            "ip": "10.10.10.10",
        },
    }
    data2, _ := json.Marshal(req2)
    data2 = append(data2, '\n')
    conn.Write(data2)
    n2, _ := conn.Read(buf)
    fmt.Printf("Block Add: %s\n", string(buf[:n2]))
    
    // Check status again
    req3 := map[string]interface{}{
        "command": "blocklist.status",
        "args": map[string]interface{}{},
    }
    data3, _ := json.Marshal(req3)
    data3 = append(data3, '\n')
    conn.Write(data3)
    n3, _ := conn.Read(buf)
    fmt.Printf("Status After Add: %s\n", string(buf[:n3]))
}
