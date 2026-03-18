#!/usr/bin/env npx tsx
/**
 * Generate DOSIPAS specimen tickets in hex encoding.
 *
 * Usage:  npx tsx scripts/generate-dosipas-tickets.ts --count 10
 *
 * Produces a CSV file (tickets.csv) with columns: serialNumber, dataHexEncoded
 */

import { parseArgs } from 'node:util';
import { writeFileSync } from 'node:fs';
import {
  decodeTicket,
  signAndEncodeTicket,
  getPublicKey,
  CURVES,
} from 'dosipas-ts';
import type { SigningKeyPair } from 'dosipas-ts';

// ── Configuration ───────────────────────────────────────────────────

const BASE_TICKET_HEX =
  '01556550004a2000000824687099c04a390100944142a84e4195c6a5264b11d492509158c00814182618330404383a14fb0b5aae64b9cad934a4d30004015038012a8908a9ea09092988a12908a98988a849e9288b172808244005008d08201a0f999b302808410008802144cc44010a268404000c32c350045a0b80080010120000100a0062a30b934b3102737b936b0b6045f62c5c37a751883186a8c4001040400000171816010a3d38d26cd5ef910257206b6e96ffa56d986faf22010a3342b79c99cb27c12f8e412ed4a52f1c347ff32480';

const L1_PRIVATE_KEY_HEX =
  'c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357';

// ── Parse CLI arguments ─────────────────────────────────────────────

const { values } = parseArgs({
  options: {
    count: { type: 'string', short: 'c' },
  },
});

const count = parseInt(values.count ?? '1', 10);
if (isNaN(count) || count < 1) {
  console.error('Error: --count must be a positive integer');
  process.exit(1);
}

// ── Build Level 1 signing key ───────────────────────────────────────

const l1PrivateKey = Uint8Array.from(
  Buffer.from(L1_PRIVATE_KEY_HEX, 'hex'),
);
const l1PublicKey = getPublicKey(l1PrivateKey, 'P-256');

const l1Key: SigningKeyPair = {
  privateKey: l1PrivateKey,
  publicKey: l1PublicKey,
  curve: 'P-256',
};

// ── Decode base ticket ──────────────────────────────────────────────

const baseTicket = decodeTicket(BASE_TICKET_HEX);

// ── Compute issuing date fields ─────────────────────────────────────

const now = new Date();
const yearStart = new Date(now.getFullYear(), 0, 1);
const issuingYear = now.getFullYear();
const issuingDay =
  Math.floor((now.getTime() - yearStart.getTime()) / (24 * 60 * 60 * 1000)) + 1;
const issuingTime = now.getUTCHours() * 60 + now.getUTCMinutes();

// ── Generate tickets ────────────────────────────────────────────────

const l1Curve = CURVES['P-256'];
const csvRows: string[] = ['serialNumber,dataHexEncoded'];

for (let i = 0; i < count; i++) {
  // Deep-clone the decoded base ticket
  const ticket = structuredClone(baseTicket);

  // Modify level1Data fields
  const l1Data = ticket.level2SignedData.level1Data;
  l1Data.securityProviderNum = 9999;
  l1Data.keyId = 0;
  l1Data.level1KeyAlg = l1Curve.keyAlgOid;
  l1Data.level1SigningAlg = l1Curve.sigAlgOid;

  // Remove level2 data
  delete ticket.level2SignedData.level2Data;
  delete ticket.level2Signature;

  // Clear raw data so the encoder re-encodes from the decoded fields
  delete l1Data.dataSequence[0].data;

  // Modify rail ticket data (first data sequence entry)
  const railData = l1Data.dataSequence[0].decoded;
  if (railData) {
    // Update issuing details
    if (railData.issuingDetail) {
      railData.issuingDetail.securityProviderNum = 9999;
      railData.issuingDetail.issuingYear = issuingYear;
      railData.issuingDetail.issuingDay = issuingDay;
      railData.issuingDetail.issuingTime = issuingTime;
      railData.issuingDetail.specimen = true;
    }

    // Remove traveler detail
    delete railData.travelerDetail;

    // Modify transport documents
    if (railData.transportDocument) {
      for (const doc of railData.transportDocument) {
        const ticketValue = doc.ticket?.value;
        if (ticketValue) {
          ticketValue.referenceNum = i;
          ticketValue.productIdNum = 55;
          ticketValue.price = 4200;
          delete ticketValue.extension;
          ticketValue.validRegion = [
            {
              key: 'zones',
              value: {
                stationCodeTable: 'stationUIC',
                city: 250065,
              },
            },
          ];
        }
      }
    }
  }

  // Sign (level 1 only, no level 2 key) and encode
  const encoded = signAndEncodeTicket(ticket, l1Key);
  const hex = Buffer.from(encoded).toString('hex');

  csvRows.push(`${i},${hex}`);
}

// ── Write CSV ───────────────────────────────────────────────────────

const outputPath = 'tickets.csv';
writeFileSync(outputPath, csvRows.join('\n') + '\n');
console.log(`Generated ${count} ticket(s) → ${outputPath}`);
