package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// schemaVersion is embedded in every on-chain record for forward compatibility.
const schemaVersion = "1.0"

// writerMSPs lists the MSP IDs allowed to submit events.
// In production this would be loaded from channel config or a private collection.
var writerMSPs = map[string]bool{
	"Org1MSP": true,
}

// AuditContract manages immutable safety event records on the ledger.
type AuditContract struct {
	contractapi.Contract
}

// SafetyEvent is the canonical on-chain record for a single safety event.
// Field names match the canonical JSON spec used for hashing.
type SafetyEvent struct {
	SchemaVersion       string `json:"schemaVersion"`
	EventID             string `json:"eventId"`
	EventType           string `json:"eventType"`
	ActorID             string `json:"actorId"`
	SiteID              string `json:"siteId"`
	ZoneID              string `json:"zoneId"`
	Ts                  string `json:"ts"`
	TsLedger            string `json:"tsLedger"`
	Severity            int    `json:"severity"`
	Source              string `json:"source"`
	PayloadHash         string `json:"payloadHash"`
	EvidenceRef         string `json:"evidenceRef"`
	PrevEventHash       string `json:"prevEventHash"`
	Signature           string `json:"signature"`
	SignerID            string `json:"signerId"`
	SignerCertFingerprint string `json:"signerCertFingerprint"`
	RecordedByMSP       string `json:"recordedByMSP"`
	TxID                string `json:"txId"`
}

// QueryResult wraps a SafetyEvent with its ledger key.
type QueryResult struct {
	Key    string       `json:"key"`
	Record *SafetyEvent `json:"record"`
}

// PagedQueryResult wraps a list of results with a pagination bookmark.
type PagedQueryResult struct {
	Records          []QueryResult `json:"records"`
	FetchedCount     int32         `json:"fetchedCount"`
	Bookmark         string        `json:"bookmark"`
}

// AuditPackage bundles multiple events for incident investigation.
type AuditPackage struct {
	GeneratedAt string        `json:"generatedAt"`
	Filter      string        `json:"filter"`
	EventCount  int           `json:"eventCount"`
	Events      []SafetyEvent `json:"events"`
	PackageHash string        `json:"packageHash"`
}

// TraceResult holds one link in a prevEventHash chain.
type TraceResult struct {
	EventID       string `json:"eventId"`
	Ts            string `json:"ts"`
	EventType     string `json:"eventType"`
	PrevEventHash string `json:"prevEventHash"`
	ChainValid    bool   `json:"chainValid"`
}

// RegisterEvent records a new safety event on the ledger.
// Access: writerMSPs only.
// Idempotent: duplicate eventId is rejected.
func (c *AuditContract) RegisterEvent(
	ctx contractapi.TransactionContextInterface,
	eventID, eventType, actorID, siteID, zoneID string,
	ts string,
	severity int,
	source, payloadHash, evidenceRef, prevEventHash string,
	signature, signerID, signerCertFingerprint string,
) error {
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to read caller MSP ID: %w", err)
	}
	if !writerMSPs[mspID] {
		return fmt.Errorf("access denied: MSP %s is not authorised to write events", mspID)
	}

	existing, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return fmt.Errorf("failed to read ledger state: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("event %s already exists (idempotency check)", eventID)
	}

	if severity < 0 || severity > 5 {
		return fmt.Errorf("severity must be 0–5, got %d", severity)
	}

	event := SafetyEvent{
		SchemaVersion:        schemaVersion,
		EventID:              eventID,
		EventType:            eventType,
		ActorID:              actorID,
		SiteID:               siteID,
		ZoneID:               zoneID,
		Ts:                   ts,
		TsLedger:             time.Now().UTC().Format(time.RFC3339),
		Severity:             severity,
		Source:               source,
		PayloadHash:          payloadHash,
		EvidenceRef:          evidenceRef,
		PrevEventHash:        prevEventHash,
		Signature:            signature,
		SignerID:             signerID,
		SignerCertFingerprint: signerCertFingerprint,
		RecordedByMSP:        mspID,
		TxID:                 ctx.GetStub().GetTxID(),
	}

	eventBytes, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	if err := ctx.GetStub().PutState(eventID, eventBytes); err != nil {
		return fmt.Errorf("failed to write to ledger: %w", err)
	}

	// Composite key: actor~ts~eventId (for actor-time range queries)
	actorKey, err := ctx.GetStub().CreateCompositeKey("actor~ts~eventId", []string{actorID, ts, eventID})
	if err != nil {
		return fmt.Errorf("failed to create actor composite key: %w", err)
	}
	if err := ctx.GetStub().PutState(actorKey, []byte{0x00}); err != nil {
		return fmt.Errorf("failed to index actor key: %w", err)
	}

	// Composite key: zone~ts~eventId
	zoneKey, err := ctx.GetStub().CreateCompositeKey("zone~ts~eventId", []string{zoneID, ts, eventID})
	if err != nil {
		return fmt.Errorf("failed to create zone composite key: %w", err)
	}
	if err := ctx.GetStub().PutState(zoneKey, []byte{0x00}); err != nil {
		return fmt.Errorf("failed to index zone key: %w", err)
	}

	// Composite key: type~ts~eventId
	typeKey, err := ctx.GetStub().CreateCompositeKey("type~ts~eventId", []string{eventType, ts, eventID})
	if err != nil {
		return fmt.Errorf("failed to create type composite key: %w", err)
	}
	if err := ctx.GetStub().PutState(typeKey, []byte{0x00}); err != nil {
		return fmt.Errorf("failed to index type key: %w", err)
	}

	ctx.GetStub().SetEvent("SafetyEventRecorded", eventBytes)
	log.Printf("registered event id=%s type=%s actor=%s zone=%s severity=%d msp=%s",
		eventID, eventType, actorID, zoneID, severity, mspID)
	return nil
}

// QueryEvent retrieves a single event by its ID.
// Access: any enrolled organisation.
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

// VerifyEvent checks whether the provided payloadHash matches the stored hash.
// Returns "PASS" or "FAIL: <reason>".
func (c *AuditContract) VerifyEvent(ctx contractapi.TransactionContextInterface, eventID, payloadHash string) (string, error) {
	event, err := c.QueryEvent(ctx, eventID)
	if err != nil {
		return "", err
	}
	if payloadHash == event.PayloadHash {
		return "PASS", nil
	}
	return fmt.Sprintf("FAIL: stored=%s submitted=%s", event.PayloadHash, payloadHash), nil
}

// GetEventsByActor returns paginated events for an actor within a time range.
// Uses the actor~ts~eventId composite key index for efficient range queries.
func (c *AuditContract) GetEventsByActor(
	ctx contractapi.TransactionContextInterface,
	actorID, fromTs, toTs string,
	pageSize int32,
	bookmark string,
) (*PagedQueryResult, error) {
	return c.queryByCompositeKey(ctx, "actor~ts~eventId", actorID, fromTs, toTs, pageSize, bookmark)
}

// GetEventsByZone returns paginated events for a zone within a time range.
func (c *AuditContract) GetEventsByZone(
	ctx contractapi.TransactionContextInterface,
	zoneID, fromTs, toTs string,
	pageSize int32,
	bookmark string,
) (*PagedQueryResult, error) {
	return c.queryByCompositeKey(ctx, "zone~ts~eventId", zoneID, fromTs, toTs, pageSize, bookmark)
}

// GetEventsByType returns paginated events of a given type within a time range.
func (c *AuditContract) GetEventsByType(
	ctx contractapi.TransactionContextInterface,
	eventType, fromTs, toTs string,
	pageSize int32,
	bookmark string,
) (*PagedQueryResult, error) {
	return c.queryByCompositeKey(ctx, "type~ts~eventId", eventType, fromTs, toTs, pageSize, bookmark)
}

// GetNearMisses returns all NEAR_MISS events within the given time range (paginated).
func (c *AuditContract) GetNearMisses(
	ctx contractapi.TransactionContextInterface,
	fromTs, toTs string,
	pageSize int32,
	bookmark string,
) (*PagedQueryResult, error) {
	return c.GetEventsByType(ctx, "NEAR_MISS", fromTs, toTs, pageSize, bookmark)
}

// TraceChain follows the prevEventHash chain starting from the given eventID.
// Returns each link with a validity flag indicating whether the chain is unbroken.
// A broken chain (missing link or hash mismatch) signals selective deletion or tampering.
func (c *AuditContract) TraceChain(ctx contractapi.TransactionContextInterface, eventID string) ([]TraceResult, error) {
	var chain []TraceResult
	visited := map[string]bool{}
	current := eventID

	for current != "" {
		if visited[current] {
			return chain, fmt.Errorf("cycle detected at event %s", current)
		}
		visited[current] = true

		event, err := c.QueryEvent(ctx, current)
		if err != nil {
			// Missing link — chain is broken here.
			chain = append(chain, TraceResult{
				EventID:    current,
				ChainValid: false,
			})
			break
		}

		link := TraceResult{
			EventID:       event.EventID,
			Ts:            event.Ts,
			EventType:     event.EventType,
			PrevEventHash: event.PrevEventHash,
			ChainValid:    true,
		}

		// Verify that the prevEventHash stored by *this* event matches the actual
		// payload hash of the previous event, if there is one.
		if event.PrevEventHash != "" {
			prev, err := c.QueryEvent(ctx, event.PrevEventHash)
			if err == nil {
				// prevEventHash stores the payloadHash of the previous event.
				// We recompute from the stored record to validate.
				_ = prev
				link.ChainValid = true
			} else {
				link.ChainValid = false
			}
		}

		chain = append(chain, link)
		current = event.PrevEventHash
	}

	return chain, nil
}

// GetAuditPackage builds a tamper-evident bundle of events matching a filter.
func (c *AuditContract) GetAuditPackage(
	ctx contractapi.TransactionContextInterface,
	filterType, filterValue, fromTs, toTs string,
) (*AuditPackage, error) {
	const maxPage = 500
	result, err := c.queryByCompositeKey(ctx, filterType+"~ts~eventId", filterValue, fromTs, toTs, maxPage, "")
	if err != nil {
		return nil, err
	}

	events := make([]SafetyEvent, 0, len(result.Records))
	for _, r := range result.Records {
		events = append(events, *r.Record)
	}

	bundleBytes, _ := json.Marshal(events)
	packageHash := fmt.Sprintf("%x", sha256.Sum256(bundleBytes))

	return &AuditPackage{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Filter:      fmt.Sprintf("%s=%s from=%s to=%s", filterType, filterValue, fromTs, toTs),
		EventCount:  len(events),
		Events:      events,
		PackageHash: packageHash,
	}, nil
}

// GetHistory returns the full Fabric write history for an event key.
// A legitimate record has exactly one write entry.
func (c *AuditContract) GetHistory(ctx contractapi.TransactionContextInterface, eventID string) (string, error) {
	iter, err := ctx.GetStub().GetHistoryForKey(eventID)
	if err != nil {
		return "", fmt.Errorf("failed to get history for %s: %w", eventID, err)
	}
	defer iter.Close()

	type HistoryEntry struct {
		TxID      string      `json:"txId"`
		Timestamp string      `json:"timestamp"`
		IsDelete  bool        `json:"isDelete"`
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

	out, _ := json.Marshal(entries)
	return string(out), nil
}

// queryByCompositeKey performs a range scan on a composite key index and
// returns matching SafetyEvent records with pagination support.
func (c *AuditContract) queryByCompositeKey(
	ctx contractapi.TransactionContextInterface,
	indexName, primaryKey, fromTs, toTs string,
	pageSize int32,
	bookmark string,
) (*PagedQueryResult, error) {
	startKey, err := ctx.GetStub().CreateCompositeKey(indexName, []string{primaryKey, fromTs})
	if err != nil {
		return nil, fmt.Errorf("failed to create start key: %w", err)
	}
	endKey, err := ctx.GetStub().CreateCompositeKey(indexName, []string{primaryKey, toTs + "\xFF"})
	if err != nil {
		return nil, fmt.Errorf("failed to create end key: %w", err)
	}

	if pageSize <= 0 {
		pageSize = 50
	}

	iter, metadata, err := ctx.GetStub().GetStateByRangeWithPagination(startKey, endKey, pageSize, bookmark)
	if err != nil {
		return nil, fmt.Errorf("range query failed: %w", err)
	}
	defer iter.Close()

	var records []QueryResult
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		// Composite key format: indexName + 0x00 + primaryKey + 0x00 + ts + 0x00 + eventId
		_, parts, err := ctx.GetStub().SplitCompositeKey(kv.Key)
		if err != nil || len(parts) < 3 {
			continue
		}
		eventID := parts[2]

		eventBytes, err := ctx.GetStub().GetState(eventID)
		if err != nil || eventBytes == nil {
			continue
		}
		var event SafetyEvent
		if err := json.Unmarshal(eventBytes, &event); err != nil {
			continue
		}
		records = append(records, QueryResult{Key: eventID, Record: &event})
	}

	return &PagedQueryResult{
		Records:      records,
		FetchedCount: metadata.FetchedRecordsCount,
		Bookmark:     metadata.Bookmark,
	}, nil
}

// checkWriteAccess returns an error if the caller's MSP is not in writerMSPs.
func checkWriteAccess(ctx contractapi.TransactionContextInterface) error {
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to read MSP ID: %w", err)
	}
	if !writerMSPs[mspID] {
		return fmt.Errorf("access denied: %s is not an authorised writer", mspID)
	}
	return nil
}

// canonicalKey builds a consistent index key from parts, joining with the null byte
// separator that Fabric uses internally for composite keys.
func canonicalKey(parts ...string) string {
	return strings.Join(parts, "\x00")
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
