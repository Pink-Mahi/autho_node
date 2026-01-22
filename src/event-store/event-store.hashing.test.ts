import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { sha256 } from '../crypto';
import { canonicalCborEncode } from '../crypto/canonical-cbor';
import { EventStore } from './event-store';
import { EventType } from './types';

describe('EventStore hashing', () => {
  it('uses canonical CBOR + domain separation for eventHash', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'autho-event-store-test-'));

    const now = 1700000000000;
    const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(now);

    try {
      const store = new EventStore(tmpDir);

      const payload = {
        type: EventType.ITEM_REGISTERED,
        timestamp: now,
        nonce: '00'.repeat(32),
        itemId: 'item-1',
        manufacturerId: 'mfg-1',
        serialNumberHash: 'serial-hash-1',
        metadataHash: 'metadata-hash-1',
        metadata: { name: 'Test' },
        initialOwner: 'owner-address',
      } as const;

      const event = await store.appendEvent(payload as any, []);

      const canonical = {
        prevEventHash: '',
        sequenceNumber: 1,
        payload,
        signatures: [],
        createdAt: now,
      };

      const domainSep = Buffer.from('AUTHO_EVT_V1_SHA256', 'utf8');
      const delimiter = Buffer.from([0x00]);
      const expectedHash = sha256(Buffer.concat([domainSep, delimiter, canonicalCborEncode(canonical)]));

      expect(event.eventHash).toBe(expectedHash);
    } finally {
      nowSpy.mockRestore();
    }
  });
});
