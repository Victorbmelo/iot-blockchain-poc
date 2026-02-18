package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// schemaVersion is embedded in every on-chain record for forward compatibility.
const schemaVersion = "1.0"

//  Role and Access Control 
//
// writerMSPs: organisations allowed to submit (write) events.
//   AuditGatewayMSP - operates the IoT gateway; submits events from the site platform.
//
// readerMSPs: organisations allowed to query and verify.
//   InspectorMSP - regulatory inspector / auditor.
//   InsurerMSP   - insurance adjuster (read + verify only).
//
// In production, replace these maps with channel-level access control policies
// defined in configtx.yaml, or with Fabric client identity attribute checks
// (ctx.GetClientIdentity().GetAttributeValue("role")).

var writerMSPs = map[string]bool{
	"AuditGatewayMSP": true,
	"Org1MSP":         true, // fabric-samples test-network alias
}

var readerMSPs = map[string]bool{
	"AuditGatewayMSP": true,
	"InspectorMSP":    true,
	"InsurerMSP":      true,
	"Org1MSP":         true,
	"Org2MSP":         true,
}

//  On-Chain Data Structures 

// SafetyEvent is the canonical on-chain record for a single auditable safety event.
// This is the formal contract for the "auditable event" unit.
//
// Fields in this struct are the single source of truth for:
//   - Chapter 4 (Implementation) - data model table
//   - Chapter 5 (Evaluation) - storage cost measurements
//   - docs/audit-event-contract.md - formal specification
type SafetyEvent struct {
	// Schema
	SchemaVersion string `json:"schemaVersion"` // "1.0" - forward-compatibility marker

	// Identity
	EventID  string `json:"eventId"`  // deterministic: SHA256(schema:actor:ts:type:zone:nonce)[0:32]
	EventType string `json:"eventType"` // see EventType constants below

	// Actors and location
	ActorID string `json:"actorId"` // pseudonymised worker or equipment ID
	SiteID  string `json:"siteId"`
	ZoneID  string `json:"zoneId"`

	// Timestamps
	Ts       string `json:"ts"`       // event time at IoT source (ISO-8601 UTC)
	TsLedger string `json:"tsLedger"` // block commit time set by chaincode (tamper-evident)

	// Severity
	Severity int `json:"severity"` // 0 (informational) to 5 (critical)

	// Source
	Source string `json:"source"` // wearable | camera | proximity_tag | gateway | simulator

	// Evidence and integrity
	PayloadHash  string `json:"payloadHash"`  // SHA-256 of canonical off-chain payload
	EvidenceRef  string `json:"evidenceRef"`  // URI of full payload in MinIO/IPFS (optional)
	PrevEventHash string `json:"prevEventHash"` // payloadHash of previous event in actor chain

	// Non-repudiation
	Signature            string `json:"signature"`            // ECDSA-P256 of payloadHash by gateway
	SignerID             string `json:"signerId"`             // gateway instance identifier
	SignerCertFingerprint string `json:"signerCertFingerprint"` // SHA-256[:16] of gateway public key

	// Accountability
	RecordedByMSP string `json:"recordedByMSP"` // Fabric MSP ID of submitting organisation
	TxID          string `json:"txId"`          // Fabric transaction ID
}

// AuditPackage bundles multiple events for incident investigation.
// The packageHash covers all included events and is computed by the chaincode,
// making it tamper-evident regardless of transport.
type AuditPackage struct {
	GeneratedAt string        `json:"generatedAt"`
	Filter      string        `json:"filter"`
	EventCount  int           `json:"eventCount"`
	Events      []SafetyEvent `json:"events"`
	PackageHash string        `json:"packageHash"` // SHA-256(canonical JSON of all events)
}

// QueryResult wraps a SafetyEvent with its ledger key for paginated responses.
type QueryResult struct {
	Key    string       `json:"key"`
	Record *SafetyEvent `json:"record"`
}

// PagedQueryResult wraps a list of results with a CouchDB pagination bookmark.
type PagedQueryResult struct {
	Records      []QueryResult `json:"records"`
	FetchedCount int32         `json:"fetchedCount"`
	Bookmark     string        `json:"bookmark"`
}

// TraceResult holds one link in a prevEventHash chain walk.
type TraceResult struct {
	EventID       string `json:"eventId"`
	Ts            string `json:"ts"`
	EventType     string `json:"eventType"`
	PrevEventHash string `json:"prevEventHash"`
	ChainValid    bool   `json:"chainValid"` // false = broken link (deletion or tampering)
}

//  AuditContract 

// AuditContract implements the chaincode for the immutable audit layer.
type AuditContract struct {
	contractapi.Contract
}

//  Write Functions (writerMSPs only) 

// RegisterEvent records a new safety event on the ledger.
//
// Access control: writerMSPs only (enforced at chaincode level, independent of gateway).
// Idempotency:    duplicate eventId is rejected - safe to retry with same nonce.
// Immutability:   PutState on existing key is blocked by the existence check;
//                 the ledger is append-only at the data model level.
//
// Endorsement: AND(AuditGatewayMSP, InspectorMSP) - configured in channel policy.
// This means the submitter cannot record events without the inspector peer co-signing.
func (c *AuditContract) RegisterEvent(
	ctx contractapi.TransactionContextInterface,
	eventID, eventType, actorID, siteID, zoneID string,
	ts string,
	severity int,
	source, payloadHash, evidenceRef, prevEventHash string,
	signature, signerID, signerCertFingerprint string,
) error {
	//  Access control 
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to read caller MSP ID: %w", err)
	}
	if !writerMSPs[mspID] {
		return fmt.Errorf("access denied: MSP %s is not authorised to write events (writerMSPs: %v)",
			mspID, writerMSPs)
	}

	//  Idempotency check 
	existing, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return fmt.Errorf("ledger read failed: %w", err)
	}
	if existing != nil {
		// Return without error - idempotent re-submission is not a failure.
		// The caller can verify the stored record matches their submission.
		return fmt.Errorf("event %s already exists (idempotency check - use GetEvent to verify)",
			eventID)
	}

	//  Input validation 
	if severity < 0 || severity > 5 {
		return fmt.Errorf("severity must be 0–5, got %d", severity)
	}
	if eventID == "" || eventType == "" || actorID == "" || payloadHash == "" {
		return fmt.Errorf("eventId, eventType, actorId, and payloadHash are required")
	}

	//  Build record 
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
		return fmt.Errorf("marshal failed: %w", err)
	}

	//  Write to ledger 
	if err := ctx.GetStub().PutState(eventID, eventBytes); err != nil {
		return fmt.Errorf("ledger write failed: %w", err)
	}

	//  Composite key indexes (enable efficient range queries without full scan) 
	for _, idx := range []struct {
		name string
		keys []string
	}{
		{"actor~ts~eventId", []string{actorID, ts, eventID}},
		{"zone~ts~eventId", []string{zoneID, ts, eventID}},
		{"type~ts~eventId", []string{eventType, ts, eventID}},
	} {
		ck, err := ctx.GetStub().CreateCompositeKey(idx.name, idx.keys)
		if err != nil {
			return fmt.Errorf("composite key creation failed for %s: %w", idx.name, err)
		}
		if err := ctx.GetStub().PutState(ck, []byte{0x00}); err != nil {
			return fmt.Errorf("index write failed for %s: %w", idx.name, err)
		}
	}

	//  Emit chaincode event (consumed by off-chain listeners) 
	ctx.GetStub().SetEvent("SafetyEventRecorded", eventBytes)

	log.Printf("registered id=%s type=%s actor=%s zone=%s severity=%d msp=%s tx=%s",
		eventID, eventType, actorID, zoneID, severity, mspID, ctx.GetStub().GetTxID())
	return nil
}

//  Read Functions (readerMSPs) 

// QueryEvent retrieves a single event by its deterministic ID.
// Access: any enrolled MSP (chaincode does not restrict reads; channel policy does).
func (c *AuditContract) QueryEvent(ctx contractapi.TransactionContextInterface, eventID string) (*SafetyEvent, error) {
	eventBytes, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return nil, fmt.Errorf("ledger read failed: %w", err)
	}
	if eventBytes == nil {
		return nil, fmt.Errorf("event %s does not exist", eventID)
	}
	var event SafetyEvent
	if err := json.Unmarshal(eventBytes, &event); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}
	return &event, nil
}

// VerifyEvent checks whether the provided payloadHash matches the stored on-chain hash.
// Returns "PASS" or "FAIL: stored=<hash> submitted=<hash>".
//
// This is the core tamper-detection operation.
// Any party holding the original payload can independently verify integrity
// without trusting the gateway or the contractor.
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
// Uses actor~ts~eventId composite key index - O(log n) range scan.
func (c *AuditContract) GetEventsByActor(
	ctx contractapi.TransactionContextInterface,
	actorID, fromTs, toTs string, pageSize int32, bookmark string,
) (*PagedQueryResult, error) {
	return c.queryByCompositeKey(ctx, "actor~ts~eventId", actorID, fromTs, toTs, pageSize, bookmark)
}

// GetEventsByZone returns paginated events for a zone within a time range.
func (c *AuditContract) GetEventsByZone(
	ctx contractapi.TransactionContextInterface,
	zoneID, fromTs, toTs string, pageSize int32, bookmark string,
) (*PagedQueryResult, error) {
	return c.queryByCompositeKey(ctx, "zone~ts~eventId", zoneID, fromTs, toTs, pageSize, bookmark)
}

// GetEventsByType returns paginated events of a specific type within a time range.
func (c *AuditContract) GetEventsByType(
	ctx contractapi.TransactionContextInterface,
	eventType, fromTs, toTs string, pageSize int32, bookmark string,
) (*PagedQueryResult, error) {
	return c.queryByCompositeKey(ctx, "type~ts~eventId", eventType, fromTs, toTs, pageSize, bookmark)
}

// GetNearMisses returns all NEAR_MISS events within the given time range.
func (c *AuditContract) GetNearMisses(
	ctx contractapi.TransactionContextInterface,
	fromTs, toTs string, pageSize int32, bookmark string,
) (*PagedQueryResult, error) {
	return c.GetEventsByType(ctx, "NEAR_MISS", fromTs, toTs, pageSize, bookmark)
}

// TraceChain follows the prevEventHash chain from eventID backward.
//
// Threat mitigation: selective deletion attack.
// If an adversary deletes an intermediate event from the ledger (impossible in Fabric,
// but possible if audit log is a conventional DB), the chain will break here.
// A break is detected when prevEventHash is non-empty but the referenced event
// cannot be found on the ledger.
func (c *AuditContract) TraceChain(ctx contractapi.TransactionContextInterface, eventID string) ([]TraceResult, error) {
	var chain []TraceResult
	visited := map[string]bool{}
	current := eventID

	for current != "" {
		if visited[current] {
			return chain, fmt.Errorf("cycle detected at event %s - chain is corrupt", current)
		}
		visited[current] = true

		event, err := c.QueryEvent(ctx, current)
		if err != nil {
			// Missing link - chain is broken here.
			chain = append(chain, TraceResult{
				EventID:    current,
				ChainValid: false,
			})
			break
		}

		chain = append(chain, TraceResult{
			EventID:       event.EventID,
			Ts:            event.Ts,
			EventType:     event.EventType,
			PrevEventHash: event.PrevEventHash,
			ChainValid:    true,
		})
		current = event.PrevEventHash
	}

	return chain, nil
}

// GetAuditPackage builds a tamper-evident bundle of events matching a filter.
// The packageHash is SHA-256 of the canonical JSON of all included events.
// Any party can recompute this hash to detect post-export tampering.
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
//
// Threat mitigation: post-write modification.
// A legitimate record has exactly one history entry (the original write).
// Two or more entries would indicate a modification attempt - which Fabric's
// append-only ledger blocks at the protocol level, but this function makes
// the proof explicit and verifiable by any auditor.
func (c *AuditContract) GetHistory(ctx contractapi.TransactionContextInterface, eventID string) (string, error) {
	iter, err := ctx.GetStub().GetHistoryForKey(eventID)
	if err != nil {
		return "", fmt.Errorf("history query failed: %w", err)
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
		resp, err := iter.Next()
		if err != nil {
			return "", err
		}
		var value interface{}
		json.Unmarshal(resp.Value, &value)
		entries = append(entries, HistoryEntry{
			TxID:      resp.TxId,
			Timestamp: time.Unix(resp.Timestamp.Seconds, 0).UTC().Format(time.RFC3339),
			IsDelete:  resp.IsDelete,
			Value:     value,
		})
	}

	out, _ := json.Marshal(entries)
	return string(out), nil
}

//  Internal helpers 

// queryByCompositeKey performs a paginated range scan on a composite key index.
// Returns matching SafetyEvent records. Uses CouchDB's ordered key structure
// so results are naturally sorted by timestamp within the primary key partition.
func (c *AuditContract) queryByCompositeKey(
	ctx contractapi.TransactionContextInterface,
	indexName, primaryKey, fromTs, toTs string,
	pageSize int32, bookmark string,
) (*PagedQueryResult, error) {
	startKey, err := ctx.GetStub().CreateCompositeKey(indexName, []string{primaryKey, fromTs})
	if err != nil {
		return nil, fmt.Errorf("start key creation failed: %w", err)
	}
	endKey, err := ctx.GetStub().CreateCompositeKey(indexName, []string{primaryKey, toTs + "\xFF"})
	if err != nil {
		return nil, fmt.Errorf("end key creation failed: %w", err)
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
		// Split composite key to extract eventId (third component)
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

func main() {
	chaincode, err := contractapi.NewChaincode(&AuditContract{})
	if err != nil {
		log.Panicf("error creating chaincode: %v", err)
	}
	if err := chaincode.Start(); err != nil {
		log.Panicf("error starting chaincode: %v", err)
	}
}
