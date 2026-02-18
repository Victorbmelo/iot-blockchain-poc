package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// AuditContract manages immutable safety event records on the ledger.
type AuditContract struct {
	contractapi.Contract
}

// SafetyEvent is the on-chain record for a single safety event.
type SafetyEvent struct {
	EventID       string `json:"event_id"`
	EventType     string `json:"event_type"`
	TsEvent       string `json:"ts_event"`
	TsIngest      string `json:"ts_ingest"`
	SiteID        string `json:"site_id"`
	ZoneID        string `json:"zone_id"`
	ActorID       string `json:"actor_id"`
	Severity      string `json:"severity"`
	Source        string `json:"source"`
	PayloadHash   string `json:"payload_hash"`
	EvidenceURI   string `json:"evidence_uri"`
	PrevEventHash string `json:"prev_event_hash"`
	TxID          string `json:"tx_id"`
	RecordedBy    string `json:"recorded_by"`
}

// QueryResult wraps a SafetyEvent with its ledger key.
type QueryResult struct {
	Key    string       `json:"key"`
	Record *SafetyEvent `json:"record"`
}

// AuditPackage bundles multiple events for incident investigation.
type AuditPackage struct {
	GeneratedAt string        `json:"generated_at"`
	Filter      string        `json:"filter"`
	EventCount  int           `json:"event_count"`
	Events      []SafetyEvent `json:"events"`
	PackageHash string        `json:"package_hash"`
}

// RegisterEvent records a new safety event on the ledger.
// Rejects duplicate event IDs to ensure idempotency.
func (c *AuditContract) RegisterEvent(
	ctx contractapi.TransactionContextInterface,
	eventID, eventType, tsEvent, siteID, zoneID, actorID,
	severity, source, payloadHash, evidenceURI, prevEventHash string,
) error {
	existing, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return fmt.Errorf("failed to read ledger state: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("event %s already exists", eventID)
	}

	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to read caller MSP ID: %w", err)
	}

	event := SafetyEvent{
		EventID:       eventID,
		EventType:     eventType,
		TsEvent:       tsEvent,
		TsIngest:      time.Now().UTC().Format(time.RFC3339),
		SiteID:        siteID,
		ZoneID:        zoneID,
		ActorID:       actorID,
		Severity:      severity,
		Source:        source,
		PayloadHash:   payloadHash,
		EvidenceURI:   evidenceURI,
		PrevEventHash: prevEventHash,
		TxID:          ctx.GetStub().GetTxID(),
		RecordedBy:    mspID,
	}

	eventBytes, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	if err := ctx.GetStub().PutState(eventID, eventBytes); err != nil {
		return fmt.Errorf("failed to write to ledger: %w", err)
	}

	ctx.GetStub().SetEvent("SafetyEventRecorded", eventBytes)
	log.Printf("registered event id=%s type=%s actor=%s zone=%s", eventID, eventType, actorID, zoneID)
	return nil
}

// QueryEvent retrieves a single event by its ID.
func (c *AuditContract) QueryEvent(ctx contractapi.TransactionContextInterface, eventID string) (*SafetyEvent, error) {
	eventBytes, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to read event %s: %w", eventID, err)
	}
	if eventBytes == nil {
		return nil, fmt.Errorf("event %s does not exist", eventID)
	}

	var event SafetyEvent
	if err := json.Unmarshal(eventBytes, &event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event: %w", err)
	}
	return &event, nil
}

// VerifyIntegrity checks whether the provided payload matches the stored hash.
// Returns "PASS" on match, or "FAIL: <reason>" on mismatch.
func (c *AuditContract) VerifyIntegrity(
	ctx contractapi.TransactionContextInterface,
	eventID, payloadJSON string,
) (string, error) {
	event, err := c.QueryEvent(ctx, eventID)
	if err != nil {
		return "", err
	}

	computed := fmt.Sprintf("%x", sha256.Sum256([]byte(payloadJSON)))
	if computed == event.PayloadHash {
		return "PASS", nil
	}
	return fmt.Sprintf("FAIL: stored=%s computed=%s", event.PayloadHash, computed), nil
}

// QueryByWorker returns all events for a given actor ID.
func (c *AuditContract) QueryByWorker(ctx contractapi.TransactionContextInterface, actorID string) ([]QueryResult, error) {
	return c.runQuery(ctx, fmt.Sprintf(`{"selector":{"actor_id":"%s"}}`, actorID))
}

// QueryByZone returns all events for a given zone ID.
func (c *AuditContract) QueryByZone(ctx contractapi.TransactionContextInterface, zoneID string) ([]QueryResult, error) {
	return c.runQuery(ctx, fmt.Sprintf(`{"selector":{"zone_id":"%s"}}`, zoneID))
}

// QueryByEventType returns all events matching the given event type.
func (c *AuditContract) QueryByEventType(ctx contractapi.TransactionContextInterface, eventType string) ([]QueryResult, error) {
	return c.runQuery(ctx, fmt.Sprintf(`{"selector":{"event_type":"%s"}}`, eventType))
}

// QueryBySeverity returns all events with the given severity level.
func (c *AuditContract) QueryBySeverity(ctx contractapi.TransactionContextInterface, severity string) ([]QueryResult, error) {
	return c.runQuery(ctx, fmt.Sprintf(`{"selector":{"severity":"%s"}}`, severity))
}

// QueryByTimeRange returns events whose ts_event falls within [startTs, endTs].
func (c *AuditContract) QueryByTimeRange(
	ctx contractapi.TransactionContextInterface,
	startTs, endTs string,
) ([]QueryResult, error) {
	query := fmt.Sprintf(`{"selector":{"ts_event":{"$gte":"%s","$lte":"%s"}}}`, startTs, endTs)
	return c.runQuery(ctx, query)
}

// QueryByZoneAndTime returns events for a zone within a time window.
func (c *AuditContract) QueryByZoneAndTime(
	ctx contractapi.TransactionContextInterface,
	zoneID, startTs, endTs string,
) ([]QueryResult, error) {
	query := fmt.Sprintf(
		`{"selector":{"zone_id":"%s","ts_event":{"$gte":"%s","$lte":"%s"}}}`,
		zoneID, startTs, endTs,
	)
	return c.runQuery(ctx, query)
}

// GetAuditPackage builds a bundle of events matching a filter, including a package hash.
func (c *AuditContract) GetAuditPackage(
	ctx contractapi.TransactionContextInterface,
	filterType, filterValue string,
) (*AuditPackage, error) {
	var results []QueryResult
	var err error

	switch filterType {
	case "actor_id":
		results, err = c.QueryByWorker(ctx, filterValue)
	case "zone_id":
		results, err = c.QueryByZone(ctx, filterValue)
	case "event_type":
		results, err = c.QueryByEventType(ctx, filterValue)
	case "severity":
		results, err = c.QueryBySeverity(ctx, filterValue)
	default:
		return nil, fmt.Errorf("unsupported filter_type %q: use actor_id, zone_id, event_type, or severity", filterType)
	}

	if err != nil {
		return nil, err
	}

	events := make([]SafetyEvent, 0, len(results))
	for _, r := range results {
		events = append(events, *r.Record)
	}

	bundleBytes, _ := json.Marshal(events)
	packageHash := fmt.Sprintf("%x", sha256.Sum256(bundleBytes))

	return &AuditPackage{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Filter:      fmt.Sprintf("%s=%s", filterType, filterValue),
		EventCount:  len(events),
		Events:      events,
		PackageHash: packageHash,
	}, nil
}

// GetHistory returns the full Fabric write history for an event key.
func (c *AuditContract) GetHistory(ctx contractapi.TransactionContextInterface, eventID string) (string, error) {
	iter, err := ctx.GetStub().GetHistoryForKey(eventID)
	if err != nil {
		return "", fmt.Errorf("failed to get history for %s: %w", eventID, err)
	}
	defer iter.Close()

	type HistoryEntry struct {
		TxID      string      `json:"tx_id"`
		Timestamp string      `json:"timestamp"`
		IsDelete  bool        `json:"is_delete"`
		Value     interface{} `json:"value"`
	}

	var entries []HistoryEntry
	for iter.HasNext() {
		response, err := iter.Next()
		if err != nil {
			return "", err
		}
		var value interface{}
		json.Unmarshal(response.Value, &value)
		entries = append(entries, HistoryEntry{
			TxID:      response.TxId,
			Timestamp: time.Unix(response.Timestamp.Seconds, 0).UTC().Format(time.RFC3339),
			IsDelete:  response.IsDelete,
			Value:     value,
		})
	}

	result, _ := json.Marshal(entries)
	return string(result), nil
}

func (c *AuditContract) runQuery(ctx contractapi.TransactionContextInterface, query string) ([]QueryResult, error) {
	iter, err := ctx.GetStub().GetQueryResult(query)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer iter.Close()

	var results []QueryResult
	for iter.HasNext() {
		response, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var event SafetyEvent
		if err := json.Unmarshal(response.Value, &event); err != nil {
			return nil, err
		}
		results = append(results, QueryResult{Key: response.Key, Record: &event})
	}
	return results, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&AuditContract{})
	if err != nil {
		log.Panicf("error creating chaincode: %v", err)
	}
	if err := chaincode.Start(); err != nil {
		log.Panicf("error starting chaincode: %v", err)
	}
}
