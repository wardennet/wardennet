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
    if len(os.Args) > 1 {
        sockPath = os.Args[1]
    }
    
    conn, err := net.Dial("unix", sockPath)
    if err != nil {
        fmt.Printf("Failed to connect: %v\n", err)
        os.Exit(1)
    }
    defer conn.Close()
    
    conn.SetDeadline(time.Now().Add(5 * time.Second))
    
    // Send status command
    req := map[string]interface{}{
        "command": "status",
        "args": map[string]interface{}{},
    }
    
    data, _ := json.Marshal(req)
    data = append(data, '\n')
    _, err = conn.Write(data)
    if err != nil {
        fmt.Printf("Failed to write: %v\n", err)
        os.Exit(1)
    }
    
    // Read response
    buf := make([]byte, 4096)
    n, err := conn.Read(buf)
    if err != nil {
        fmt.Printf("Failed to read: %v\n", err)
        os.Exit(1)
    }
    
    fmt.Printf("Response: %s\n", string(buf[:n]))
    
    // Send blocklist status command
    req2 := map[string]interface{}{
        "command": "blocklist.status",
        "args": map[string]interface{}{},
    }
    
    data2, _ := json.Marshal(req2)
    data2 = append(data2, '\n')
    _, err = conn.Write(data2)
    if err != nil {
        fmt.Printf("Failed to write: %v\n", err)
        os.Exit(1)
    }
    
    n2, err := conn.Read(buf)
    if err != nil {
        fmt.Printf("Failed to read: %v\n", err)
        os.Exit(1)
    }
    
    fmt.Printf("Blocklist Response: %s\n", string(buf[:n2]))
}
