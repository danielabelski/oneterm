package file

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/singleflight"
	"gorm.io/gorm"

	"github.com/veops/oneterm/internal/guacd"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	gsession "github.com/veops/oneterm/internal/session"
	"github.com/veops/oneterm/internal/tunneling"
	"github.com/veops/oneterm/pkg/sshclient"
)

var (
	// Legacy asset-based file manager
	fm = &FileManager{entries: map[string]*fileClientEntry{}}

	// New session-based file manager
	sessionFM = &SessionFileManager{
		sessionSFTP: make(map[string]*sftp.Client),
		sessionSSH:  make(map[string]*ssh.Client),
		lastActive:  make(map[string]time.Time),
	}

	// Session file transfer manager
	sessionTransferManager = &SessionFileTransferManager{
		transfers: make(map[string]*SessionFileTransfer),
	}

	// Progress tracking state
	fileTransfers = make(map[string]*FileTransferProgress)
	transferMutex sync.RWMutex
)

// Session-based file operation errors
var (
	ErrSessionNotFound  = errors.New("session not found")
	ErrSessionClosed    = errors.New("session has been closed")
	ErrSessionInactive  = errors.New("session is inactive")
	ErrSFTPNotAvailable = errors.New("SFTP not available for this session")
)

// Global getter functions
func GetFileManager() *FileManager {
	return fm
}

func GetSessionFileManager() *SessionFileManager {
	return sessionFM
}

func GetSessionTransferManager() *SessionFileTransferManager {
	return sessionTransferManager
}

// FileInfo represents file information
type FileInfo struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	IsLink  bool   `json:"is_link"`
	Target  string `json:"target"`
	ModTime string `json:"mod_time"`
}

// FileManager manages SFTP connections (legacy asset-based)
type FileManager struct {
	entries map[string]*fileClientEntry
	mtx     sync.Mutex
	inits   singleflight.Group
}

type fileClientEntry struct {
	tunnelID string
	client   *sftp.Client
	owner    *ssh.Client
	active   int
	lastUsed time.Time
}

func (fm *FileManager) Acquire(ctx context.Context, assetId, accountId int) (*sftp.Client, func(), error) {
	key := fmt.Sprintf("%d-%d", assetId, accountId)
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		fm.mtx.Lock()
		entry := fm.entries[key]
		if entry != nil {
			entry.active++
			fm.mtx.Unlock()
			var once sync.Once
			release := func() {
				once.Do(func() { fm.mtx.Lock(); entry.active--; entry.lastUsed = time.Now(); fm.mtx.Unlock() })
			}
			return entry.client, release, nil
		}
		fm.mtx.Unlock()
		result := fm.inits.DoChan(key, func() (any, error) {
			fm.mtx.Lock()
			existing := fm.entries[key]
			fm.mtx.Unlock()
			if existing != nil {
				return existing, nil
			}
			bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			entry, err := dialFileClient(bounded, assetId, accountId)
			if err != nil {
				return nil, err
			}
			fm.mtx.Lock()
			var oldestKey string
			var oldest *fileClientEntry
			if len(fm.entries) >= 256 {
				for candidate, current := range fm.entries {
					if current.active == 0 && (oldest == nil || current.lastUsed.Before(oldest.lastUsed)) {
						oldestKey, oldest = candidate, current
					}
				}
				if oldest == nil {
					fm.mtx.Unlock()
					entry.close()
					return nil, errors.New("SFTP connection capacity reached")
				}
				delete(fm.entries, oldestKey)
			}
			fm.entries[key] = entry
			fm.mtx.Unlock()
			if oldest != nil {
				oldest.close()
			}
			return entry, nil
		})
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case result := <-result:
			if result.Err != nil {
				return nil, nil, result.Err
			}
		}
	}
}

var legacySFTPInitializations = make(chan struct{}, 16)

func dialFileClient(ctx context.Context, assetId, accountId int) (*fileClientEntry, error) {
	select {
	case legacySFTPInitializations <- struct{}{}:
		defer func() { <-legacySFTPInitializations }()
	default:
		return nil, errors.New("SFTP connection capacity reached")
	}
	asset, account, gateway, err := repository.GetAAG(assetId, accountId)
	if err != nil {
		return nil, err
	}

	tunnelID := uuid.NewString()
	retained := false
	defer func() {
		if !retained {
			tunneling.CloseTunnels(tunnelID)
		}
	}()
	ip, port, err := tunneling.Proxy(false, tunnelID, "sftp,ssh", asset, gateway)
	if err != nil {
		return nil, err
	}

	auth, err := repository.GetAuth(account)
	if err != nil {
		return nil, err
	}

	targetHost, targetPort, err := tunneling.Target("sftp,ssh", asset)
	if err != nil {
		return nil, err
	}
	sshCli, err := sshclient.Dial(ctx, net.JoinHostPort(ip, strconv.Itoa(port)), &ssh.ClientConfig{
		User:            account.Account,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: sshclient.HostKey(net.JoinHostPort(targetHost, strconv.Itoa(targetPort))),
		Timeout:         time.Second,
	})
	if err != nil {
		return nil, err
	}

	stop := context.AfterFunc(ctx, func() { sshCli.Close() })
	defer stop()
	// Create optimized SFTP client
	cli, err := sftp.NewClient(sshCli,
		sftp.MaxPacket(32768),                 // 32KB packets for maximum compatibility
		sftp.MaxConcurrentRequestsPerFile(16), // Increase concurrent requests
		sftp.UseConcurrentWrites(true),        // Enable concurrent writes
		sftp.UseConcurrentReads(true),         // Enable concurrent reads
		sftp.UseFstat(false),                  // Disable fstat for better compatibility
	)
	if err != nil {
		sshCli.Close()
		return nil, err
	}
	retained = true
	return &fileClientEntry{client: cli, owner: sshCli, tunnelID: tunnelID, lastUsed: time.Now()}, nil
}

func (entry *fileClientEntry) close() {
	entry.client.Close()
	entry.owner.Close()
	if entry.tunnelID != "" {
		tunneling.CloseTunnels(entry.tunnelID)
	}
}

func (fm *FileManager) CleanupIdle(now time.Time, idle time.Duration) {
	var expired []*fileClientEntry
	fm.mtx.Lock()
	for key, entry := range fm.entries {
		if entry.active == 0 && now.Sub(entry.lastUsed) >= idle {
			delete(fm.entries, key)
			expired = append(expired, entry)
		}
	}
	fm.mtx.Unlock()
	for _, entry := range expired {
		entry.close()
	}
}

// SessionFileManager manages SFTP connections per session
type SessionFileManager struct {
	sessionSFTP map[string]*sftp.Client // sessionId -> SFTP client
	sessionSSH  map[string]*ssh.Client  // sessionId -> SSH client
	lastActive  map[string]time.Time    // sessionId -> last active time
	mutex       sync.RWMutex
	inits       singleflight.Group
}

func (sfm *SessionFileManager) InitSessionSFTP(sessionId string, assetId, accountId int) error {
	session := gsession.GetOnlineSessionById(sessionId)
	if session == nil || session.Session == nil || session.AssetId != assetId || session.AccountId != accountId {
		return ErrSessionNotFound
	}
	if !session.IsSsh() {
		return ErrSFTPNotAvailable
	}
	_, err, _ := sfm.inits.Do(sessionId, func() (any, error) { return nil, sfm.initSessionSFTP(sessionId, assetId, accountId) })
	return err
}

func (sfm *SessionFileManager) initSessionSFTP(sessionId string, assetId, accountId int) error {
	session := gsession.GetOnlineSessionById(sessionId)
	if session == nil || session.Session == nil || session.AssetId != assetId || session.AccountId != accountId {
		return ErrSessionNotFound
	}
	if !session.IsSsh() {
		return ErrSFTPNotAvailable
	}
	if session.Gctx == nil || session.Gctx.Err() != nil {
		return ErrSessionClosed
	}
	sfm.mutex.Lock()
	if _, exists := sfm.sessionSFTP[sessionId]; exists {
		sfm.lastActive[sessionId] = time.Now()
		sfm.mutex.Unlock()
		return nil
	}
	sfm.mutex.Unlock()
	client := session.GetSSHClient()
	owned := client == nil
	if owned {
		asset, account, gateway, err := repository.GetAAG(assetId, accountId)
		if err != nil {
			return err
		}
		host, port, err := tunneling.Target(session.Protocol, asset)
		if err != nil {
			return err
		}
		identity := net.JoinHostPort(host, strconv.Itoa(port))
		host, port, err = tunneling.Proxy(false, sessionId, session.Protocol, asset, gateway)
		if err != nil {
			return err
		}
		auth, err := repository.GetAuth(account)
		if err != nil {
			return err
		}
		client, err = sshclient.Dial(session.Gctx, net.JoinHostPort(host, strconv.Itoa(port)), &ssh.ClientConfig{
			User: account.Account, Auth: []ssh.AuthMethod{auth}, HostKeyCallback: sshclient.HostKey(identity), Timeout: 10 * time.Second})
		if err != nil {
			return err
		}
	}
	sftpClient, err := sftp.NewClient(client, sftp.MaxPacket(32768), sftp.MaxConcurrentRequestsPerFile(16),
		sftp.UseConcurrentWrites(true), sftp.UseConcurrentReads(true), sftp.UseFstat(false))
	if err != nil {
		if owned {
			client.Close()
		}
		return err
	}
	sfm.mutex.Lock()
	if session.Gctx.Err() != nil {
		sfm.mutex.Unlock()
		sftpClient.Close()
		if owned {
			client.Close()
		}
		return ErrSessionClosed
	}
	sfm.sessionSFTP[sessionId] = sftpClient
	if owned {
		sfm.sessionSSH[sessionId] = client
	}
	sfm.lastActive[sessionId] = time.Now()
	sfm.mutex.Unlock()
	return nil
}

func (sfm *SessionFileManager) GetSessionSFTP(sessionId string) (*sftp.Client, error) {
	session := gsession.GetOnlineSessionById(sessionId)
	if session == nil || session.Session == nil {
		return nil, ErrSessionNotFound
	}
	if !session.IsSsh() {
		return nil, ErrSFTPNotAvailable
	}
	if session.Gctx == nil || session.Gctx.Err() != nil {
		return nil, ErrSessionClosed
	}
	if client, err := sfm.getCachedSessionSFTP(sessionId); err == nil {
		return client, nil
	}
	if err := sfm.InitSessionSFTP(sessionId, session.AssetId, session.AccountId); err != nil {
		return nil, err
	}
	return sfm.getCachedSessionSFTP(sessionId)
}

func (sfm *SessionFileManager) getCachedSessionSFTP(sessionId string) (*sftp.Client, error) {
	sfm.mutex.Lock()
	defer sfm.mutex.Unlock()

	client, exists := sfm.sessionSFTP[sessionId]
	if !exists {
		return nil, ErrSessionNotFound
	}

	// Update last active time
	sfm.lastActive[sessionId] = time.Now()
	return client, nil
}

func (sfm *SessionFileManager) CloseSessionSFTP(sessionId string) {
	sfm.closeSessionSFTP(sessionId, time.Time{})
}

func (sfm *SessionFileManager) closeSessionSFTP(sessionId string, cutoff time.Time) {
	sfm.mutex.Lock()
	if !cutoff.IsZero() && sfm.lastActive[sessionId].After(cutoff) {
		sfm.mutex.Unlock()
		return
	}
	sftpClient, client := sfm.sessionSFTP[sessionId], sfm.sessionSSH[sessionId]
	delete(sfm.sessionSFTP, sessionId)
	delete(sfm.sessionSSH, sessionId)
	delete(sfm.lastActive, sessionId)
	sfm.mutex.Unlock()
	if sftpClient != nil {
		sftpClient.Close()
	}
	if client != nil {
		client.Close()
	}
}

func (sfm *SessionFileManager) IsSessionActive(sessionId string) bool {
	session := gsession.GetOnlineSessionById(sessionId)
	return session != nil && session.Session != nil && session.IsSsh() && session.Gctx != nil && session.Gctx.Err() == nil
}

func (sfm *SessionFileManager) CleanupInactiveSessions(timeout time.Duration) {
	var ids []string
	cutoff := time.Now().Add(-timeout)
	sfm.mutex.Lock()
	for id, last := range sfm.lastActive {
		if last.Before(cutoff) {
			ids = append(ids, id)
		}
	}
	sfm.mutex.Unlock()
	for _, id := range ids {
		sfm.closeSessionSFTP(id, cutoff)
	}
}

func (sfm *SessionFileManager) GetActiveSessionCount() int {
	sfm.mutex.RLock()
	defer sfm.mutex.RUnlock()
	return len(sfm.sessionSFTP)
}

// IFileService defines the file service interface
type IFileService interface {
	// Legacy asset-based operations (for backward compatibility)
	ReadDir(ctx context.Context, assetId, accountId int, dir string) ([]fs.FileInfo, error)
	MkdirAll(ctx context.Context, assetId, accountId int, dir string) error
	Create(ctx context.Context, assetId, accountId int, path string) (io.WriteCloser, error)
	Open(ctx context.Context, assetId, accountId int, path string) (io.ReadCloser, error)
	Stat(ctx context.Context, assetId, accountId int, path string) (fs.FileInfo, error)
	DownloadMultiple(ctx context.Context, assetId, accountId int, dir string, filenames []string) (io.ReadCloser, string, int64, error)

	// Session-based operations (NEW - high performance)
	SessionLS(ctx context.Context, sessionId, dir string) ([]FileInfo, error)
	SessionMkdir(ctx context.Context, sessionId, dir string) error
	SessionUpload(ctx context.Context, sessionId, targetPath string, file io.Reader, filename string, size int64) error
	SessionUploadWithID(ctx context.Context, transferID, sessionId, targetPath string, file io.Reader, filename string, size int64) error
	SessionDownload(ctx context.Context, sessionId, filePath string) (io.ReadCloser, int64, error)
	SessionDownloadMultiple(ctx context.Context, sessionId, dir string, filenames []string) (io.ReadCloser, string, int64, error)

	// Session lifecycle management
	InitSessionFileClient(sessionId string, assetId, accountId int) error
	CloseSessionFileClient(sessionId string)
	IsSessionActive(sessionId string) bool

	// Progress tracking for session transfers
	GetSessionTransferProgress(ctx context.Context, sessionId string) ([]*SessionFileTransferProgress, error)
	GetTransferProgress(ctx context.Context, transferId string) (*SessionFileTransferProgress, error)

	// File history and other operations
	AddFileHistory(ctx context.Context, history *model.FileHistory) error
	BuildFileHistoryQuery(ctx *gin.Context) *gorm.DB
	RecordFileHistory(ctx context.Context, operation, dir, filename string, assetId, accountId int, sessionId ...string) error
	RecordFileHistoryBySession(ctx context.Context, sessionId, operation, path string) error

	// Utility methods
	GetActionCode(operation string) int
	ValidateAndNormalizePath(basePath, userPath string) (string, error)
	GetRDPDrivePath(assetId int) (string, error)
}

// FileService implements IFileService
type FileService struct {
	repo repository.IFileRepository
}

// RDP File related structures
type RDPFileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time"`
}

type RDPMkdirRequest struct {
	Path string `json:"path" binding:"required"`
}

type RDPProgressWriter struct {
	writer     io.Writer
	transfer   *guacd.FileTransfer
	transferId string
	written    int64
}

// Session transfer related structures
type SessionFileTransfer struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	Filename  string    `json:"filename"`
	Size      int64     `json:"size"`
	Offset    int64     `json:"offset"`
	Status    string    `json:"status"` // "pending", "uploading", "completed", "failed"
	IsUpload  bool      `json:"is_upload"`
	Created   time.Time `json:"created"`
	Updated   time.Time `json:"updated"`
	Error     string    `json:"error,omitempty"`
	mutex     sync.Mutex
}

type SessionFileTransferProgress struct {
	ID         string    `json:"id"`
	SessionID  string    `json:"session_id"`
	Filename   string    `json:"filename"`
	Size       int64     `json:"size"`
	Offset     int64     `json:"offset"`
	Percentage float64   `json:"percentage"`
	Status     string    `json:"status"`
	IsUpload   bool      `json:"is_upload"`
	Created    time.Time `json:"created"`
	Updated    time.Time `json:"updated"`
	Error      string    `json:"error,omitempty"`
	Speed      int64     `json:"speed"` // bytes per second
	ETA        int64     `json:"eta"`   // estimated time to completion in seconds
}

type SessionFileTransferManager struct {
	transfers map[string]*SessionFileTransfer
	mutex     sync.RWMutex
}

func (m *SessionFileTransferManager) CreateTransfer(sessionID, filename string, size int64, isUpload bool) *SessionFileTransfer {
	return m.CreateTransferWithID(generateTransferID(), sessionID, filename, size, isUpload)
}

func (m *SessionFileTransferManager) CreateTransferWithID(transferID, sessionID, filename string, size int64, isUpload bool) *SessionFileTransfer {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	transfer := &SessionFileTransfer{
		ID:        transferID,
		SessionID: sessionID,
		Filename:  filename,
		Size:      size,
		Offset:    0,
		Status:    "pending",
		IsUpload:  isUpload,
		Created:   time.Now(),
		Updated:   time.Now(),
	}

	m.transfers[transferID] = transfer
	return transfer
}

func (m *SessionFileTransferManager) GetTransfer(id string) *SessionFileTransfer {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.transfers[id]
}

func (m *SessionFileTransferManager) GetTransfersBySession(sessionID string) []*SessionFileTransfer {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var transfers []*SessionFileTransfer
	for _, transfer := range m.transfers {
		if transfer.SessionID == sessionID {
			transfers = append(transfers, transfer)
		}
	}
	return transfers
}

func (m *SessionFileTransferManager) GetSessionProgress(sessionID string) []*SessionFileTransferProgress {
	transfers := m.GetTransfersBySession(sessionID)
	var progressList []*SessionFileTransferProgress
	for _, transfer := range transfers {
		progressList = append(progressList, transfer.GetProgress())
	}
	return progressList
}

func (m *SessionFileTransferManager) RemoveTransfer(id string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.transfers, id)
}

func (m *SessionFileTransferManager) CleanupCompletedTransfers(maxAge time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for id, transfer := range m.transfers {
		if (transfer.Status == "completed" || transfer.Status == "failed") && transfer.Updated.Before(cutoff) {
			delete(m.transfers, id)
		}
	}
}

// Progress tracking structures
type FileTransferProgress struct {
	OwnerUID        int
	Scope           string
	active          bool
	expiresAt       time.Time
	TotalSize       int64
	TransferredSize int64
	Status          string // "transferring", "completed", "failed"
	Type            string // "sftp", "rdp"
}

type ProgressWriter struct {
	writer   io.Writer
	transfer *SessionFileTransfer
	written  int64
}

func NewProgressWriter(writer io.Writer, transfer *SessionFileTransfer) *ProgressWriter {
	return &ProgressWriter{
		writer:   writer,
		transfer: transfer,
		written:  0,
	}
}

func (pw *ProgressWriter) Write(p []byte) (int, error) {
	n, err := pw.writer.Write(p)
	if n > 0 {
		pw.written += int64(n)
		pw.transfer.UpdateProgress(pw.written)
	}

	if err != nil {
		pw.transfer.SetError(err)
	}

	return n, err
}

type FileProgressWriter struct {
	writer       io.Writer
	transferId   string
	written      int64
	lastUpdate   time.Time
	updateBytes  int64 // Bytes written since last progress update
	updateTicker int64 // Simple counter to reduce time.Now() calls
}

func NewFileProgressWriter(writer io.Writer, transferId string) *FileProgressWriter {
	return &FileProgressWriter{
		writer:     writer,
		transferId: transferId,
		written:    0,
		lastUpdate: time.Now(),
	}
}

func (pw *FileProgressWriter) Write(p []byte) (int, error) {
	n, err := pw.writer.Write(p)
	if n > 0 {
		pw.written += int64(n)
		pw.updateBytes += int64(n)
		pw.updateTicker++

		// Update progress every 256KB or every 500 writes to reduce memory overhead
		// Larger intervals reduce GC pressure and memory fragmentation
		if pw.updateBytes >= 262144 || pw.updateTicker%500 == 0 {
			UpdateTransferProgress(pw.transferId, 0, pw.written, "transferring")
			pw.updateBytes = 0
			pw.lastUpdate = time.Now()
		}
	}

	if err != nil {
		UpdateTransferProgress(pw.transferId, 0, -1, "failed")
	}

	return n, err
}

// SessionFileTransfer methods
func (t *SessionFileTransfer) UpdateProgress(offset int64) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.Offset = offset
	t.Updated = time.Now()

	if t.Status == "pending" {
		t.Status = "uploading"
	}

	if t.Size > 0 && t.Offset >= t.Size {
		t.Status = "completed"
	}
}

func (t *SessionFileTransfer) SetError(err error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.Error = err.Error()
	t.Status = "failed"
	t.Updated = time.Now()
}

// GetProgress returns the current progress information
func (t *SessionFileTransfer) GetProgress() *SessionFileTransferProgress {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	var percentage float64
	if t.Size > 0 {
		percentage = float64(t.Offset) / float64(t.Size) * 100
	}

	// Calculate speed and ETA
	var speed int64
	var eta int64
	if !t.Created.Equal(t.Updated) && t.Offset > 0 {
		duration := t.Updated.Sub(t.Created).Seconds()
		speed = int64(float64(t.Offset) / duration)

		if speed > 0 && t.Size > t.Offset {
			eta = (t.Size - t.Offset) / speed
		}
	}

	return &SessionFileTransferProgress{
		ID:         t.ID,
		SessionID:  t.SessionID,
		Filename:   t.Filename,
		Size:       t.Size,
		Offset:     t.Offset,
		Percentage: percentage,
		Status:     t.Status,
		IsUpload:   t.IsUpload,
		Created:    t.Created,
		Updated:    t.Updated,
		Error:      t.Error,
		Speed:      speed,
		ETA:        eta,
	}
}

// Progress tracking functions
var (
	ErrTransferProgressInput    = errors.New("invalid transfer progress request")
	ErrTransferProgressConflict = errors.New("transfer progress is unavailable")
	ErrTransferProgressCapacity = errors.New("transfer progress capacity reached")
)

func CreateTransferProgress(transferId, transferType string, uid int, scope string, active bool) error {
	if uid <= 0 || transferId == "" || len(transferId) > 128 || scope == "" || (transferType != "sftp" && transferType != "rdp") {
		return ErrTransferProgressInput
	}
	transferMutex.Lock()
	defer transferMutex.Unlock()
	now := time.Now()
	if previous := fileTransfers[transferId]; previous != nil {
		if !previous.active && !now.Before(previous.expiresAt) {
			delete(fileTransfers, transferId)
		} else {
			if previous.OwnerUID != uid || previous.Scope != scope || previous.Type != transferType {
				return ErrTransferProgressConflict
			}
			if !active {
				return nil
			}
			if previous.active || previous.Status == "completed" {
				return ErrTransferProgressConflict
			}
			previous.active = true
			previous.Status = "transferring"
			previous.TotalSize = 0
			previous.TransferredSize = 0
			previous.expiresAt = time.Time{}
			return nil
		}
	}
	if len(fileTransfers) >= 8192 {
		cleanupExpiredTransfersLocked(now)
	}
	if len(fileTransfers) >= 8192 {
		return ErrTransferProgressCapacity
	}
	status := "prepared"
	expires := now.Add(2 * time.Minute)
	if active {
		status = "transferring"
		expires = time.Time{}
	}
	fileTransfers[transferId] = &FileTransferProgress{OwnerUID: uid, Scope: scope, Status: status, Type: transferType, active: active, expiresAt: expires}
	return nil
}

func UpdateTransferProgress(transferId string, totalSize, transferredSize int64, status string) {
	transferMutex.Lock()
	if progress, exists := fileTransfers[transferId]; exists {
		if totalSize > 0 {
			progress.TotalSize = totalSize
		}
		if transferredSize >= 0 {
			progress.TransferredSize = transferredSize
		}
		if status != "" {
			progress.Status = status
		}
	}
	transferMutex.Unlock()
}

func CleanupTransferProgress(transferId string, delay time.Duration) {
	transferMutex.Lock()
	defer transferMutex.Unlock()
	if delay <= 0 {
		delete(fileTransfers, transferId)
		return
	}
	if progress := fileTransfers[transferId]; progress != nil {
		progress.active = false
		progress.expiresAt = time.Now().Add(delay)
		if progress.Status == "transferring" {
			progress.Status = "failed"
		}
	}
}

func CleanupExpiredTransfers(now time.Time) {
	transferMutex.Lock()
	defer transferMutex.Unlock()
	cleanupExpiredTransfersLocked(now)
}

func cleanupExpiredTransfersLocked(now time.Time) {
	for id, progress := range fileTransfers {
		if !progress.active && !now.Before(progress.expiresAt) {
			delete(fileTransfers, id)
		}
	}
}

func GetTransferProgressById(transferId string) (*FileTransferProgress, bool) {
	transferMutex.RLock()
	defer transferMutex.RUnlock()
	progress, exists := fileTransfers[transferId]
	if !exists || (!progress.active && !time.Now().Before(progress.expiresAt)) {
		return nil, false
	}
	snapshot := *progress
	return &snapshot, true
}

// Utility functions
func generateTransferID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func sanitizeFilename(filename string) (string, error) {
	// Remove any directory separators
	cleaned := filepath.Base(filename)

	// Check for dangerous patterns
	if strings.Contains(cleaned, "..") || cleaned == "." || cleaned == "" {
		return "", fmt.Errorf("invalid filename")
	}

	// Additional security checks
	if strings.HasPrefix(cleaned, ".") && len(cleaned) > 1 {
		// Allow hidden files but validate they're not dangerous
	}

	return cleaned, nil
}

func IsPermissionError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())
	permissionKeywords := []string{
		"permission denied",
		"access denied",
		"unauthorized",
		"forbidden",
		"not authorized",
		"insufficient privileges",
		"operation not permitted",
		"sftp: permission denied",
		"ssh: permission denied",
	}

	for _, keyword := range permissionKeywords {
		if strings.Contains(errStr, keyword) {
			return true
		}
	}

	return false
}
