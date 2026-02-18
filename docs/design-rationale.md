# Design Rationale

## The Central Question

A common challenge for blockchain-based systems is: "Why not use a simpler solution?"

Specifically for this system, the question is:

> Why not use an append-only database with digital signatures, instead of Hyperledger Fabric?

This document answers that question formally and precisely. The answer defines the boundary between decorative blockchain use and justified blockchain use.

## What an Append-Only Database with Digital Signatures Provides

An append-only database (e.g., PostgreSQL with row-level write protection + application-layer signature) provides:

- **Data integrity:** A signed record can be verified to have originated from a known private key.
- **Append-only semantics (application-layer):** The application refuses to delete or overwrite records.
- **Audit trail:** All records are retained and queryable.

This is sufficient when there is a single trusted administrator and all parties trust that administrator.

## Why This Is Insufficient for Construction Site Safety Accountability

### Problem 1: Single Point of Trust

An append-only database is only as trustworthy as its administrator. In the construction site context:

- The database is typically operated by the **main contractor** — the party with the strongest incentive to suppress evidence of negligence after an incident.
- The contractor's system administrator can disable the append-only constraint, modify records directly at the database level, or restore the database from a backup that predates an inconvenient event.
- A digital signature proves the record originated from a specific key. It does not prevent the key owner from signing a replacement record after deleting the original.

**The fundamental gap:** A single-party system cannot provide accountability to *that same party*. The contractor cannot be held accountable by a log they control.

### Problem 2: No Shared, Independent State

Insurance adjusters, site inspectors, and regulators cannot independently verify the state of the contractor's database. They receive an export that the contractor prepared. There is no way to confirm the export reflects the actual database state.

To verify independently, they would need:
- Direct database access (which the contractor will not grant), or
- A trusted third party to maintain a copy (which introduces another single point of trust and significant operational cost)

### Problem 3: No Non-Repudiation Across Parties

Non-repudiation requires that neither party can deny having participated in a transaction. A digital signature on a single-party database proves the record was signed by a specific key — but it does not prevent that party from claiming the signature was forged or the timestamp was wrong, because no independent party witnessed the transaction.

## What Hyperledger Fabric Adds

Fabric addresses each of these gaps directly:

### Multi-Party Endorsement Eliminates Single Point of Trust

Every transaction must be endorsed by a configurable set of organisations before it is committed to the ledger. In this system, both Org1 (contractor) and Org2 (inspector/insurer) must sign each write transaction.

This means:
- The contractor cannot silently insert or modify records — the inspector's peer must endorse it.
- The inspector cannot fabricate records and blame the contractor — the contractor's peer must also have signed.
- Neither party can unilaterally rewrite history.

**The property this provides:** Mutual non-repudiation. Both parties' signatures are required, and both parties' signatures are on record.

### Distributed Ledger Eliminates the Single Administrator Problem

Each endorsing organisation maintains its own copy of the ledger. There is no single database that a single administrator controls. For records to be altered retroactively:
- All copies of the ledger held by all organisations would need to be modified simultaneously
- The block hashes (each block contains the hash of the previous block) would need to be recomputed and re-signed for all subsequent blocks
- All ordering nodes would need to collude

This is computationally and organisationally infeasible in a multi-party deployment.

### Ordering Service Provides Independent Timestamping

The RAFT ordering service assigns a globally ordered sequence number and timestamp to each transaction. This timestamp is included in the block header and is not settable by the submitting organisation. It provides an independent, auditable timestamp that neither the contractor nor the inspector controls.

### Cryptographic Audit Trail Is Publicly Verifiable

Any party with read access to the ledger can independently verify:
- That a specific transaction exists
- That it was endorsed by the expected organisations
- That the payload hash matches the original data
- That no subsequent write has modified the record (write history returns a single entry)

This verification requires no trust in any single party — it is a mathematical property of the ledger structure.

## Formal Comparison

| Property | Append-Only DB + Signature | Hyperledger Fabric |
|---|---|---|
| Record integrity | Yes (hash + signature) | Yes (hash + multi-signature) |
| Tamper detection | Yes, if the signature is checked | Yes, verifiable by any party |
| Single administrator risk | **No** — admin can bypass | **Yes** — no single admin controls all copies |
| Independent verification | **No** — requires trusting the exporter | **Yes** — any org can verify independently |
| Non-repudiation | Partial — one party's signature | **Yes** — all endorsing orgs signed |
| Shared state across distrusting parties | **No** — each party has their own copy | **Yes** — consensus-agreed shared ledger |
| Retroactive modification | Technically possible by admin | Computationally infeasible |
| Evidence admissibility | Requires trust in a third party | Self-evidencing with cryptographic proof |

## When the Simpler Solution Would Be Sufficient

The append-only database approach would be sufficient if:
- There is a single trusted party responsible for maintaining the log (e.g., a fully independent regulator who all parties trust)
- That party has no financial stake in the outcome of any dispute
- All other parties are willing to accept that party's export as ground truth

In construction sites, this condition is not met. The entity that operates the IoT platform (typically the main contractor) is also the primary party whose liability is in question after an incident.

## Conclusion

The use of Hyperledger Fabric in this system is justified by a specific, concrete gap in simpler solutions: the need to provide tamper-evident records that are credible to *all* stakeholders, including the party operating the logging infrastructure.

The key property is **multi-stakeholder accountability without a trusted intermediary**. This is the property that permissioned blockchain provides and that no single-administrator database can replicate.

This does not mean blockchain is always the right choice. It is the right choice specifically when:
1. Multiple parties with conflicting interests need to share a tamper-evident record
2. No single party is trusted by all others
3. The records may be used as legal evidence in future disputes
4. The parties are known and permissioned (ruling out public blockchains)

All four conditions are met in this system.
