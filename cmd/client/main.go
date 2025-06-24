package main
import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"golang.org/x/crypto/ssh"
)

type Message struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Timestamp int64  `json:"timestamp"`
	Subject   string `json:"subject"`
	Body      string `json:"body"`
	Nonce     string `json:"nonce"`
	Sig       string `json:"sig,omitempty"`
}

type AuthMessage struct {
	Username string  `json:"username"`
	Message  Message `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

type Account struct {
	Username    string `json:"username"`
	BangAddress string `json:"bang_address"`
	Created     int64  `json:"created"`
}

type Client struct{}

func (c *Client) createAccount(bangAddress string) error {
	username, domain, err := c.parseAddress(bangAddress)
	if err != nil {
		return err
	}
	
	port := 2222
	if portStr := os.Getenv("BANGMAIL_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	
	client, err := c.createSSHClient(domain, port)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", domain, err)
	}
	defer client.Close()	
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()	
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	
	cmd := fmt.Sprintf("bangmail-create-account %s %s", username, bangAddress)
	if err := session.Start(cmd); err != nil {
		return err
	}
	
	response, err := io.ReadAll(stdout)
	if err != nil {
		return err
	}
	
	if err := session.Wait(); err != nil {
		return err
	}
	
	if strings.TrimSpace(string(response)) != "OK" {
		return fmt.Errorf("server error: %s", string(response))
	}
	
	return c.saveAccount(username, bangAddress)
}

func (c *Client) getConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".bangmail")
}

func (c *Client) getAccountPath(username string) string {
	return filepath.Join(c.getConfigPath(), username+".account")
}

func (c *Client) saveAccount(username, bangAddress string) error {
	configPath := c.getConfigPath()
	if err := os.MkdirAll(configPath, 0755); err != nil {
		return err
	}
	
	account := &Account{
		Username:    username,
		BangAddress: bangAddress,
		Created:     time.Now().Unix(),
	}
	
	accountData, err := json.Marshal(account)
	if err != nil {
		return err
	}
	
	accountPath := c.getAccountPath(username)
	return os.WriteFile(accountPath, accountData, 0644)
}

func (c *Client) getAccount(username string) (*Account, error) {
	accountPath := c.getAccountPath(username)	
	data, err := os.ReadFile(accountPath)
	if err != nil {
		return nil, err
	}
	
	var account Account
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, err
	}
	
	return &account, nil
}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) parseAddress(addr string) (string, string, error) {
	parts := strings.Split(addr, "!")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid address format, expected user!domain")
	}
	return parts[0], parts[1], nil
}

func (c *Client) createSSHClient(host string, port int) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: "bangmail",
		Auth: []ssh.AuthMethod{
			ssh.Password(""),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	
	addr := fmt.Sprintf("%s:%d", host, port)
	return ssh.Dial("tcp", addr, config)
}

func (c *Client) generateNonce() string {
	nonce := make([]byte, 12)
	rand.Read(nonce)
	return base64.StdEncoding.EncodeToString(nonce)
}

func (c *Client) sendMessage(to, from, subject, body string) error {
	fromUser, _, err := c.parseAddress(from)
	if err != nil {
		return err
	}
	
	account, err := c.getAccount(fromUser)
	if err != nil {
		return fmt.Errorf("account not found for %s, create it first with: bangmail create %s", fromUser, from)
	}
	
	if account.BangAddress != from {
		return fmt.Errorf("from address doesn't match stored account")
	}
	
	_, targetDomain, err := c.parseAddress(to)
	if err != nil {
		return err
	}
	
	port := 2222
	if portStr := os.Getenv("BANGMAIL_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	
	client, err := c.createSSHClient(targetDomain, port)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", targetDomain, err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()	
	msg := &Message{
		From:      from,
		To:        to,
		Timestamp: time.Now().Unix(),
		Subject:   subject,
		Body:      body,
		Nonce:     c.generateNonce(),
	}
	
	authMsg := &AuthMessage{
		Username: fromUser,
		Message:  *msg,
		Timestamp: account.Created,
	}
	
	msgData, err := json.Marshal(authMsg)
	if err != nil {
		return err
	}
	
	toUser, _, _ := c.parseAddress(to)
	cmd := fmt.Sprintf("bangmail-receive %s", toUser)
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	
	if err := session.Start(cmd); err != nil {
		return err
	}
	
	go func() {
		defer stdin.Close()
		stdin.Write(msgData)
	}()
	
	response, err := io.ReadAll(stdout)
	if err != nil {
		return err
	}
	
	if err := session.Wait(); err != nil {
		return err
	}
	
	if strings.TrimSpace(string(response)) != "OK" {
		return fmt.Errorf("server error: %s", string(response))
	}
	
	return nil
}

func (c *Client) fetchMessages(addr string) ([]*Message, error) {
	user, domain, err := c.parseAddress(addr)
	if err != nil {
		return nil, err
	}
	
	port := 2222
	if portStr := os.Getenv("BANGMAIL_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	
	client, err := c.createSSHClient(domain, port)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", domain, err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}
  
	account, err := c.getAccount(user)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("bangmail-fetch %s %d", user, account.Created)
	if err := session.Start(cmd); err != nil {
		return nil, err
	}
	
	var messages []*Message
	scanner := bufio.NewScanner(stdout)	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		
		if strings.HasPrefix(line, "ERROR:") {
			continue
		}
		
		var msg Message
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		
		messages = append(messages, &msg)
	}
	
	session.Wait()
	
	return messages, nil
}

func usage() {
	fmt.Println("Usage:")
	fmt.Println("  bangmail create <bang_address>")
	fmt.Println("  bangmail send <to> [options]")
	fmt.Println("  bangmail fetch <address>")
	fmt.Println("")
	fmt.Println("Create account:")
	fmt.Println("  bangmail create alice!example.com")
	fmt.Println("")
	fmt.Println("Send options:")
	fmt.Println("  --from <address>    sender address (must be created first)")
	fmt.Println("  --subject <text>    message subject")
	fmt.Println("  --body <text>       message body")
	fmt.Println("  --stdin             read body from stdin")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  bangmail create alice!example.com")
	fmt.Println("  bangmail send neo!neoapps.dev --from alice!example.com --subject 'Hello' --body 'Test message'")
	fmt.Println("  bangmail fetch alice!example.com")
	fmt.Println("  echo 'message body' | bangmail send neo!neoapps.dev --from alice!example.com --subject 'Hello' --stdin")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	
	client := NewClient()
	command := os.Args[1]	
	switch command {
	case "create":
		if len(os.Args) < 3 {
			usage()
			os.Exit(1)
		}
		
		bangAddress := os.Args[2]
		if err := client.createAccount(bangAddress); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating account: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Printf("Account created successfully: %s\n", bangAddress)
		
	case "send":
		if len(os.Args) < 3 {
			usage()
			os.Exit(1)
		}
		
		to := os.Args[2]
		args := os.Args[3:]
		
		var from, subject, body string
		var useStdin bool
		
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--from":
				if i+1 < len(args) {
					from = args[i+1]
					i++
				}
			case "--subject":
				if i+1 < len(args) {
					subject = args[i+1]
					i++
				}
			case "--body":
				if i+1 < len(args) {
					body = args[i+1]
					i++
				}
			case "--stdin":
				useStdin = true
			}
		}
		
		if useStdin {
			bodyBytes, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
				os.Exit(1)
			}
			body = string(bodyBytes)
		}
		
		if from == "" {
			fmt.Fprintf(os.Stderr, "Error: --from is required\n")
			os.Exit(1)
		}
		
		if err := client.sendMessage(to, from, subject, body); err != nil {
			fmt.Fprintf(os.Stderr, "Error sending message: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Println("Message sent successfully")
		
	case "fetch":
		if len(os.Args) < 3 {
			usage()
			os.Exit(1)
		}
		
		addr := os.Args[2]
		messages, err := client.fetchMessages(addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching messages: %v\n", err)
			os.Exit(1)
		}
		
		if len(messages) == 0 {
			fmt.Println("No messages")
			return
		}
		
		for _, msg := range messages {
			fmt.Printf("From: %s\n", msg.From)
			fmt.Printf("To: %s\n", msg.To)
			fmt.Printf("Subject: %s\n", msg.Subject)
			fmt.Printf("Date: %s\n", time.Unix(msg.Timestamp, 0).Format(time.RFC3339))
			fmt.Printf("Body: %s\n", msg.Body)
			fmt.Println("---")
		}
		
	default:
		usage()
		os.Exit(1)
	}
}
