// Package db provides an encrypted SQLite-backed scan history database
// using AES-256-GCM encryption with PBKDF2 key derivation, zero CGO
// (via modernc.org/sqlite).
package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/pbkdf2"
	_ "modernc.org/sqlite"

	"github.com/SepJs/anubis/pkg/scanner"
)

type HistoryDB struct {
	db        *sql.DB
	encKey    []byte
	enabled   bool
}

type ScanRecord struct {
	ID        int64     `json:"id"`
	Target    string    `json:"target"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Duration  string    `json:"duration"`
	Level     int       `json:"level"`
	Findings  int       `json:"findings"`
	RiskScore float64   `json:"risk_score"`
	Result    string    `json:"result,omitempty"`
}

func NewHistoryDB(path string, encrypt bool, passkey string) (*HistoryDB, error) {
	if path == "" {
		path = "anubis_history.db"
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("db: ping: %w", err)
	}

	h := &HistoryDB{db: db, enabled: true}

	if encrypt && passkey != "" {
		h.encKey = h.deriveKey(passkey)
	}

	if err := h.migrate(); err != nil {
		return nil, fmt.Errorf("db: migrate: %w", err)
	}

	return h, nil
}

func (h *HistoryDB) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL,
			start_time TEXT NOT NULL,
			end_time TEXT,
			duration TEXT,
			level INTEGER NOT NULL,
			findings_count INTEGER DEFAULT 0,
			risk_score REAL DEFAULT 0,
			result TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			severity TEXT NOT NULL,
			type TEXT,
			confidence TEXT,
			endpoint TEXT,
			parameter TEXT,
			cvss_score REAL,
			description TEXT,
			evidence TEXT,
			remediation TEXT,
			owasp_mapping TEXT,
			discovered_at TEXT,
			FOREIGN KEY (scan_id) REFERENCES scans(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(start_time)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)`,
	}

	for _, q := range queries {
		if _, err := h.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (h *HistoryDB) SaveScan(result *scanner.ScanResult) (int64, error) {
	if !h.enabled {
		return 0, nil
	}

	resultJSON, _ := json.Marshal(result)
	resultStr := string(resultJSON)

	if h.encKey != nil {
		encrypted, err := h.encrypt(resultStr)
		if err != nil {
			return 0, fmt.Errorf("db: encrypt: %w", err)
		}
		resultStr = encrypted
	}

	res, err := h.db.Exec(
		`INSERT INTO scans (target, start_time, end_time, duration, level, findings_count, risk_score, result)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		result.Target,
		result.StartTime.Format(time.RFC3339),
		result.EndTime.Format(time.RFC3339),
		result.Duration.String(),
		int(result.ScanLevel),
		result.Summary.TotalFindings,
		result.Summary.RiskScore,
		resultStr,
	)
	if err != nil {
		return 0, fmt.Errorf("db: insert scan: %w", err)
	}

	scanID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	for _, finding := range result.AllFindings {
		_, err := h.db.Exec(
			`INSERT INTO findings (scan_id, title, severity, type, confidence, endpoint, parameter, cvss_score, description, evidence, remediation, owasp_mapping, discovered_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			scanID, finding.Title, string(finding.Severity), string(finding.Type),
			string(finding.Confidence), finding.Endpoint, finding.Parameter,
			finding.CVSSScore, finding.Description, finding.Evidence,
			finding.Remediation, finding.OWASPMapping,
			finding.DiscoveredAt.Format(time.RFC3339),
		)
		if err != nil {
			return scanID, fmt.Errorf("db: insert finding: %w", err)
		}
	}

	return scanID, nil
}

func (h *HistoryDB) RecentScans(limit int) ([]ScanRecord, error) {
	if !h.enabled {
		return nil, nil
	}

	rows, err := h.db.Query(
		`SELECT id, target, start_time, end_time, duration, level, findings_count, risk_score
		FROM scans ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("db: query: %w", err)
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		var r ScanRecord
		var startStr, endStr string
		if err := rows.Scan(&r.ID, &r.Target, &startStr, &endStr, &r.Duration, &r.Level, &r.Findings, &r.RiskScore); err != nil {
			return nil, err
		}
		r.StartTime, _ = time.Parse(time.RFC3339, startStr)
		r.EndTime, _ = time.Parse(time.RFC3339, endStr)
		records = append(records, r)
	}
	return records, nil
}

func (h *HistoryDB) GetScan(id int64) (*scanner.ScanResult, error) {
	if !h.enabled {
		return nil, fmt.Errorf("database not enabled")
	}

	var resultStr string
	err := h.db.QueryRow(`SELECT result FROM scans WHERE id = ?`, id).Scan(&resultStr)
	if err != nil {
		return nil, fmt.Errorf("db: get scan: %w", err)
	}

	if h.encKey != nil {
		decrypted, err := h.decrypt(resultStr)
		if err != nil {
			return nil, fmt.Errorf("db: decrypt: %w", err)
		}
		resultStr = decrypted
	}

	var result scanner.ScanResult
	if err := json.Unmarshal([]byte(resultStr), &result); err != nil {
		return nil, fmt.Errorf("db: unmarshal: %w", err)
	}

	return &result, nil
}

func (h *HistoryDB) Stats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	var totalScans int
	h.db.QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&totalScans)
	stats["total_scans"] = totalScans

	var totalFindings int
	h.db.QueryRow(`SELECT COALESCE(SUM(findings_count), 0) FROM scans`).Scan(&totalFindings)
	stats["total_findings"] = totalFindings

	row := h.db.QueryRow(`SELECT AVG(risk_score) FROM scans WHERE risk_score > 0`)
	var avgRisk sql.NullFloat64
	row.Scan(&avgRisk)
	stats["avg_risk_score"] = avgRisk.Float64

	return stats, nil
}

func (h *HistoryDB) Close() error {
	if h.db != nil {
		return h.db.Close()
	}
	return nil
}

func (h *HistoryDB) deriveKey(passkey string) []byte {
	salt := []byte("AnubisScanHistory2024")
	key := pbkdf2.Key([]byte(passkey), salt, 100000, 32, sha256.New)
	return key
}

func (h *HistoryDB) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(h.encKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

func (h *HistoryDB) decrypt(cipherHex string) (string, error) {
	ciphertext, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(h.encKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func (h *HistoryDB) ExportAll(w io.Writer) error {
	records, err := h.RecentScans(1000)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(records)
}

type NullDB struct{}

func NewNullDB() *NullDB {
	return &NullDB{}
}

func (n *NullDB) SaveScan(result *scanner.ScanResult) (int64, error) {
	return 0, nil
}

func (n *NullDB) Close() error {
	return nil
}

func init() {
	os.Setenv("SQLITE_BUSY_TIMEOUT", "5000")
}
