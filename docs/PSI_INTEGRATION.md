# Private Set Intersection

## Overview

Rendezvous uses Private Set Intersection for match queries. When you query
for your matches, the server never learns which tokens you submitted.

**Privacy guarantees:**

| Party | Learns | Does NOT Learn |
|-------|--------|----------------|
| Server | Message sizes, timing | Your tokens or matches |
| You | Your matches only | Others' non-matching tokens |
| Federation | Nothing (Freebird tokens) | Who is participating |

## Data Flow

```
1. SUBMISSION PHASE
   - Participants submit matchTokens + encryptedReveal
   - Server stores tokens (but doesn't compare them)

2. POOL CLOSES (revealDeadline passes)
   - PSI setup created from all submitted tokens

3. QUERY PHASE
   - POST /api/pools/:id/query-matches with your tokens
   - Server processes PSI request (learns nothing)
   - You compute intersection locally

4. REVEAL PHASE
   - Request reveal data for your matched tokens
   - Decrypt contact info for mutual matches
```

## API Usage

```typescript
// 1. Create PSI request from your tokens
const { psiRequest, clientKey } = await fetch('/api/psi/create-request', {
  method: 'POST',
  body: JSON.stringify({ inputs: myTokens })
}).then(r => r.json())

// 2. Query the pool
const { psiSetup, psiResponse } = await fetch(`/api/pools/${poolId}/query-matches`, {
  method: 'POST',
  body: JSON.stringify({ psiRequest, authToken: freebirdToken })
}).then(r => r.json())

// 3. Compute intersection locally - only YOU learn your matches
const { intersection } = await fetch('/api/psi/compute-intersection', {
  method: 'POST',
  body: JSON.stringify({ clientKey, inputs: myTokens, psiSetup, psiResponse })
}).then(r => r.json())

console.log('Your matches:', intersection)
```

## Federation

With PSI + Freebird, cross-instance queries are fully private:

```
Instance A                    Instance B (pool owner)
    │                                │
    │  1. Get Freebird token         │
    │     (anonymous auth)           │
    │                                │
    │  2. Relay PSI request ────────►│
    │     (no instance ID)           │
    │                                │
    │  3. Process PSI ◄──────────────│
    │                                │
    │  4. Compute intersection       │
    │     locally                    │
```

Neither instance learns your preferences. Only you learn your matches.

## Security Notes

**False Positives:** PSI uses Bloom filters with configurable false positive
rate (default 0.1%). Verify matches by attempting contact.

**Timing:** Random delays and response padding mitigate timing analysis.

**Server Key:** PSI server key is encrypted at rest, never exposed in responses.

## Dependencies

```bash
npm install @openmined/psi.js
```
