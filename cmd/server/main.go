package main
import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"github.com/gliderlabs/ssh"
	"regexp"
	"errors"
)

var validUsername = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)
func isValidUsername(u string) bool {
    return validUsername.MatchString(u)
}

type Message struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Timestamp int64  `json:"timestamp"`
	Subject   string `json:"subject"`
	Body      string `json:"body"`
	Nonce     string `json:"nonce"`
	Sig       string `json:"sig,omitempty"`
}

type Account struct {
	Username    string `json:"username"`
	BangAddress string `json:"bang_address"`
	Created     int64  `json:"created"`
}

type AuthMessage struct {
	Username string  `json:"username"`
	Timestamp int64  `json:"timestamp"`
	Message  Message `json:"message"`
}

type Server struct {
	key         []byte
	inboxPath   string
	accountPath string
}

func NewServer() (*Server, error) {
	keyStr := os.Getenv("BANGMAIL_KEY")
	if keyStr == "" {
		return nil, fmt.Errorf("BANGMAIL_KEY environment variable required")
	}
	
	hash := sha256.Sum256([]byte(keyStr))
	key := hash[:]
	inboxPath := os.Getenv("BANGMAIL_INBOX_PATH")
	if inboxPath == "" {
		inboxPath = "/var/lib/bangmail/inbox"
	}
	
	accountPath := os.Getenv("BANGMAIL_ACCOUNT_PATH")
	if accountPath == "" {
		accountPath = "/var/lib/bangmail/accounts"
	}
	
	return &Server{
		key:         key,
		inboxPath:   inboxPath,
		accountPath: accountPath,
	}, nil
}

func (s *Server) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (s *Server) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}

func (s *Server) getAccountPath(username string) string {
	return filepath.Join(s.accountPath, username+".bang.account")
}

func (s *Server) createAccount(username, bangAddress string) error {
	if !isValidUsername(username) {
		return errors.New("invalid username")
	}
	if err := os.MkdirAll(s.accountPath, 0755); err != nil {
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
	
	encrypted, err := s.encrypt(accountData)
	if err != nil {
		return err
	}
	
	accountPath := s.getAccountPath(username)
	return os.WriteFile(accountPath, encrypted, 0644)
}

func (s *Server) getAccount(username string) (*Account, error) {
	accountPath := s.getAccountPath(username)
	data, err := os.ReadFile(accountPath)
	if err != nil {
		return nil, err
	}
	
	decrypted, err := s.decrypt(data)
	if err != nil {
		return nil, err
	}
	
	var account Account
	if err := json.Unmarshal(decrypted, &account); err != nil {
		return nil, err
	}
	
	return &account, nil
}

func (s *Server) authenticateUser(username, fromAddress string, created int64) error {
	account, err := s.getAccount(username)
	if err != nil {
		return fmt.Errorf("account not found")
	}
	
	if account.BangAddress != fromAddress {
		return fmt.Errorf("authentication failed: address mismatch")
	}

	if account.Created != created {
		return fmt.Errorf("authentication failed: timestamp mismatch")
	}
	
	return nil
}

func (s *Server) getUserInboxPath(username string) string {
	return filepath.Join(s.inboxPath, username)
}

func (s *Server) storeMessage(username string, msg *Message) error {
	inboxPath := s.getUserInboxPath(username)
	if err := os.MkdirAll(inboxPath, 0755); err != nil {
		return err
	}
	
	msgData, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	
	encrypted, err := s.encrypt(msgData)
	if err != nil {
		return err
	}
	
	filename := fmt.Sprintf("msg-%d.bmail", time.Now().UnixNano())
	filepath := filepath.Join(inboxPath, filename)
	return os.WriteFile(filepath, encrypted, 0644)
}

func (s *Server) fetchMessages(username string) ([]*Message, error) {
	inboxPath := s.getUserInboxPath(username)	
	files, err := os.ReadDir(inboxPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []*Message{}, nil
		}
		return nil, err
	}
	
	var messages []*Message
	var filesToDelete []string
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".bmail") {
			continue
		}
		
		filepath := filepath.Join(inboxPath, file.Name())
		data, err := os.ReadFile(filepath)
		if err != nil {
			continue
		}
		
		decrypted, err := s.decrypt(data)
		if err != nil {
			continue
		}
		
		var msg Message
		if err := json.Unmarshal(decrypted, &msg); err != nil {
			continue
		}
		
		messages = append(messages, &msg)
		filesToDelete = append(filesToDelete, filepath)
	}
	
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Timestamp < messages[j].Timestamp
	})
	
	for _, filepath := range filesToDelete {
		os.Remove(filepath)
	}
	
	return messages, nil
}

func (s *Server) handleReceive(sess ssh.Session, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(sess, "ERROR: recipient required")
		return
	}
	
	recipient := args[0]
	scanner := bufio.NewScanner(sess)
	var msgData []byte
	for scanner.Scan() {
		msgData = append(msgData, scanner.Bytes()...)
		msgData = append(msgData, '\n')
	}
	
	if len(msgData) == 0 {
		fmt.Fprintln(sess, "ERROR: no message data")
		return
	}
	
	var authMsg AuthMessage
	if err := json.Unmarshal(msgData, &authMsg); err != nil {
		fmt.Fprintln(sess, "ERROR: invalid message format")
		return
	}
	
	if err := s.authenticateUser(authMsg.Username, authMsg.Message.From, authMsg.Timestamp); err != nil {
		fmt.Fprintln(sess, "ERROR: authentication failed")
		return
	}
	
	authMsg.Message.To = recipient
	authMsg.Message.Timestamp = time.Now().Unix()
	if len(authMsg.Message.Subject) > 256 {
		fmt.Fprintln(sess, "ERROR: subject too long (>256)")
		return
	}

	if len(authMsg.Message.Body) > 10000 {
		fmt.Fprintln(sess, "ERROR: body too long (>10000)")
		return
	}
	
	if err := s.storeMessage(recipient, &authMsg.Message); err != nil {
		fmt.Fprintln(sess, "ERROR: failed to store message")
		return
	}
	
	fmt.Fprintln(sess, "OK")
}

func (s *Server) handleFetch(sess ssh.Session, args []string) {
	if len(args) < 2 {
		fmt.Fprintln(sess, "ERROR: username and timestamp required")
		return
	}
	
	username := args[0]
	timestamp_string := args[1]
	timestamp, error := strconv.ParseInt(timestamp_string, 10, 64)
	if error != nil {
		fmt.Fprintln(sess, "ERROR: ", error)
		return
	}
	if _, err := s.getAccount(username); err != nil {
		fmt.Fprintln(sess, "ERROR: account not found")
		return
	}
	
	account, _ := s.getAccount(username)
	if account.Created != timestamp {
		fmt.Fprintln(sess, "ERROR: authentication failed: timestamp mismatch")
		return
	}
	
	messages, err := s.fetchMessages(username)
	if err != nil {
		fmt.Fprintln(sess, "ERROR: failed to fetch messages")
		return
	}
	
	for _, msg := range messages {
		msgData, err := json.Marshal(msg)
		if err != nil {
			continue
		}
		fmt.Fprintln(sess, string(msgData))
	}
}

func (s *Server) handleCreateAccount(sess ssh.Session, args []string) {
	if len(args) < 2 {
		fmt.Fprintln(sess, "ERROR: username and bang_address required")
		return
	}
	
	username := args[0]
	bangAddress := args[1]	
	if _, err := s.getAccount(username); err == nil {
		fmt.Fprintln(sess, "ERROR: account already exists")
		return
	}
	
	if err := s.createAccount(username, bangAddress); err != nil {
		fmt.Fprintln(sess, "ERROR: failed to create account")
		return
	}
	
	fmt.Fprintln(sess, "OK")
}

func (s *Server) handleConnection(sess ssh.Session) {
	cmd := sess.Command()
	if len(cmd) == 0 {
		fmt.Fprintln(sess, "ERROR: no command specified")
		return
	}
	
	parts := strings.Fields(strings.Join(cmd, " "))
	command := parts[0]
	args := parts[1:]
	switch command {
	case "bangmail-receive":
		s.handleReceive(sess, args)
	case "bangmail-fetch":
		s.handleFetch(sess, args)
	case "bangmail-create-account":
		s.handleCreateAccount(sess, args)
	default:
		fmt.Fprintln(sess, "ERROR: unknown command")
	}
}

func main() {
	server, err := NewServer()
	if err != nil {
		log.Fatal(err)
	}
	
	port := os.Getenv("BANGMAIL_PORT")
	if port == "" {
		port = "2222"
	}
	
	ssh.Handle(func(sess ssh.Session) {
		server.handleConnection(sess)
	})
	
	log.Printf("Starting Bangmail server on port %s", port)
	log.Fatal(ssh.ListenAndServe(":"+port, nil))
}
