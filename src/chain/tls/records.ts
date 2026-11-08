/**
 * TLS 记录层与握手消息（原 _worker.js L3369-3393 常量表 + L3558-3710 解析/构造，行为等价移植）。
 * 含记录封装、握手分片解析、ServerHello / ServerKeyExchange / 叶子证书 / EncryptedExtensions
 * 解析与 ClientHello 构造，以及密码套件等常量。
 */
import { toUint8Array } from '../../utils/bytes';
import { constantTimeEqual, EMPTY_BYTES } from './primitives';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function tlsBytes(...parts: Array<number | Uint8Array | number[]>): Uint8Array {
  const flattenBytes = (values: unknown[]): number[] =>
    values.flatMap((value) =>
      value instanceof Uint8Array ? [...value] : Array.isArray(value) ? flattenBytes(value as unknown[]) : typeof value === 'number' ? [value] : [],
    );
  return new Uint8Array(flattenBytes(parts as unknown[]));
}
const uint16be = (value: number): number[] => [(value >> 8) & 255, value & 255];
export const readUint16 = (buffer: Uint8Array, offset: number): number => (buffer[offset]! << 8) | buffer[offset + 1]!;
export const readUint24 = (buffer: Uint8Array, offset: number): number => ((buffer[offset]! << 16) | (buffer[offset + 1]! << 8) | buffer[offset + 2]!) >>> 0;

function concatBytes(...chunks: Array<Uint8Array | number[] | null | undefined>): Uint8Array {
  const nonEmpty = chunks.filter((c): c is Uint8Array | number[] => !!c && c.length > 0);
  let total = 0;
  for (const c of nonEmpty) total += c.length;
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of nonEmpty) {
    result.set(chunk instanceof Uint8Array ? chunk : Uint8Array.from(chunk), offset);
    offset += chunk.length;
  }
  return result;
}

export const TLS_VERSION_10 = 769, TLS_VERSION_12 = 771, TLS_VERSION_13 = 772;
export const CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20, CONTENT_TYPE_ALERT = 21, CONTENT_TYPE_HANDSHAKE = 22, CONTENT_TYPE_APPLICATION_DATA = 23;
export const HANDSHAKE_TYPE_CLIENT_HELLO = 1, HANDSHAKE_TYPE_SERVER_HELLO = 2, HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8, HANDSHAKE_TYPE_CERTIFICATE = 11, HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12, HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13, HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14, HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16, HANDSHAKE_TYPE_FINISHED = 20, HANDSHAKE_TYPE_KEY_UPDATE = 24;
export const EXT_SERVER_NAME = 0, EXT_SUPPORTED_GROUPS = 10, EXT_EC_POINT_FORMATS = 11, EXT_SIGNATURE_ALGORITHMS = 13, EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, EXT_SUPPORTED_VERSIONS = 43, EXT_PSK_KEY_EXCHANGE_MODES = 45, EXT_KEY_SHARE = 51;

export const ALERT_CLOSE_NOTIFY = 0, ALERT_LEVEL_WARNING = 1, ALERT_UNRECOGNIZED_NAME = 112;
export const shouldIgnoreTlsAlert = (fragment: Uint8Array | null | undefined): boolean => fragment?.[0] === ALERT_LEVEL_WARNING && fragment?.[1] === ALERT_UNRECOGNIZED_NAME;




export const CIPHER_SUITES_BY_ID = new Map([
	[4865, { id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0 }],
	[4866, { id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0 }],
	[4867, { id: 4867, keyLen: 32, ivLen: 12, hash: "SHA-256", tls13: !0, chacha: !0 }],
	[49199, { id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49200, { id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52392, { id: 52392, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }],
	[49195, { id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49196, { id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52393, { id: 52393, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }]
]);
export const GROUPS_BY_ID = new Map([[29, "X25519"], [23, "P-256"]]);
export const SUPPORTED_SIGNATURE_ALGORITHMS = [2052, 2053, 2054, 1025, 1281, 1537, 1027, 1283, 1539];

export function buildTlsRecord(contentType: number, fragment: Uint8Array, version = TLS_VERSION_12): Uint8Array {
	const data = toUint8Array(fragment);
	const record = new Uint8Array(5 + data.byteLength);
	record[0] = contentType;
	record[1] = version >> 8 & 255;
	record[2] = version & 255;
	record[3] = data.byteLength >> 8 & 255;
	record[4] = data.byteLength & 255;
	record.set(data, 5);
	return record;
}
export function buildHandshakeMessage(handshakeType: number, body: Uint8Array): Uint8Array { return tlsBytes(handshakeType, (length => [length >> 16 & 255, length >> 8 & 255, 255 & length])(body.length), body) }
export class TlsRecordParser {
	private buffer: Uint8Array = new Uint8Array(0)
	feed(chunk: Uint8Array): void {
		const bytes = toUint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next(): { type: number; version: number; length: number; fragment: Uint8Array } | null {
		if (this.buffer.length < 5) return null;
		const contentType = this.buffer[0]!;
		const version = readUint16(this.buffer, 1);
		const length = readUint16(this.buffer, 3);
		if (this.buffer.length < 5 + length) return null;
		const fragment = this.buffer.subarray(5, 5 + length);
		this.buffer = this.buffer.subarray(5 + length);
		return { type: contentType, version, length, fragment };
	}
}
export class TlsHandshakeParser {
	private buffer: Uint8Array = new Uint8Array(0)
	feed(chunk: Uint8Array): void {
		const bytes = toUint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next(): { type: number; length: number; body: Uint8Array; raw: Uint8Array } | null {
		if (this.buffer.length < 4) return null;
		const handshakeType = this.buffer[0]!;
		const length = readUint24(this.buffer, 1);
		if (this.buffer.length < 4 + length) return null;
		const body = this.buffer.subarray(4, 4 + length);
		const raw = this.buffer.subarray(0, 4 + length);
		this.buffer = this.buffer.subarray(4 + length);
		return { type: handshakeType, length, body, raw };
	}
}

export const TLS_MAX_PLAINTEXT_FRAGMENT = 16 * 1024;

export function parseServerHello(body: Uint8Array) {
	let offset = 0;
	const legacyVersion = readUint16(body, offset);
	offset += 2;
	const serverRandom = body.slice(offset, offset + 32);
	offset += 32;
	const sessionIdLength = body[offset++]!;
	const sessionId = body.slice(offset, offset + sessionIdLength);
	offset += sessionIdLength;
	const cipherSuite = readUint16(body, offset);
	offset += 2;
	const compression = body[offset++];
	let selectedVersion = legacyVersion,
		keyShare = null,
		alpn = null;
	if (offset < body.length) {
		const extensionsLength = readUint16(body, offset);
		offset += 2;
		const extensionsEnd = offset + extensionsLength;
		for (; offset + 4 <= extensionsEnd;) {
			const extensionType = readUint16(body, offset);
			offset += 2;
			const extensionLength = readUint16(body, offset);
			offset += 2;
			const extensionData = body.slice(offset, offset + extensionLength);
			if (offset += extensionLength, extensionType === EXT_SUPPORTED_VERSIONS && extensionLength >= 2) selectedVersion = readUint16(extensionData, 0);
			else if (extensionType === EXT_KEY_SHARE && extensionLength >= 4) {
				const group = readUint16(extensionData, 0),
					keyLength = readUint16(extensionData, 2);
				keyShare = { group, key: extensionData.slice(4, 4 + keyLength) }
			} else extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3 && (alpn = textDecoder.decode(extensionData.slice(3, 3 + extensionData[2]!)))
		}
	}
	const helloRetryRequestRandom = new Uint8Array([207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]);
	return { version: legacyVersion, serverRandom, sessionId, cipherSuite, compression, selectedVersion, keyShare, alpn, isHRR: constantTimeEqual(serverRandom, helloRetryRequestRandom), isTls13: selectedVersion === TLS_VERSION_13 }
}

export function parseServerKeyExchange(body: Uint8Array) {
	let offset = 1;
	const namedCurve = readUint16(body, offset);
	offset += 2;
	const keyLength = body[offset++]!;
	return { namedCurve, serverPublicKey: body.slice(offset, offset + keyLength) }
}

export function extractLeafCertificate(body: Uint8Array, hasContext: number | boolean = 0) {
	let offset = 0;
	if (hasContext) {
		const contextLength = body[offset++]!;
		offset += contextLength
	}
	if (offset + 3 > body.length) return null;
	const certificateListLength = readUint24(body, offset);
	if (offset += 3, !certificateListLength || offset + 3 > body.length) return null;
	const certificateLength = readUint24(body, offset);
	return offset += 3, certificateLength ? body.slice(offset, offset + certificateLength) : null
}

export function parseEncryptedExtensions(body: Uint8Array) {
	const parsed: { alpn: string | null } = { alpn: null };
	let offset = 2;
	const extensionsEnd = 2 + readUint16(body, 0);
	for (; offset + 4 <= extensionsEnd;) {
		const extensionType = readUint16(body, offset);
		offset += 2;
		const extensionLength = readUint16(body, offset);
		if (offset += 2, extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3) {
			const protocolLength = body[offset + 2]!;
			protocolLength > 0 && offset + 3 + protocolLength <= offset + extensionLength && (parsed.alpn = textDecoder.decode(body.slice(offset + 3, offset + 3 + protocolLength)))
		}
		offset += extensionLength
	}
	return parsed
}

export function buildClientHello(
  clientRandom: Uint8Array,
  serverName: string,
  keyShares: { x25519?: Uint8Array; p256?: Uint8Array } | Uint8Array | null,
  { tls13: enableTls13 = true, tls12: enableTls12 = true, alpn = null, chacha = true }: { tls13?: boolean; tls12?: boolean; alpn?: string | string[] | null; chacha?: boolean } = {},
): Uint8Array {
	const cipherIds = [];
	enableTls13 && cipherIds.push(4865, 4866, ...(chacha ? [4867] : [])), enableTls12 && cipherIds.push(49199, 49200, 49195, 49196, ...(chacha ? [52392, 52393] : []));
	const cipherBytes = tlsBytes(...cipherIds.flatMap(uint16be)),
		extensions = [tlsBytes(255, 1, 0, 1, 0)];
	if (serverName) {
		const serverNameBytes = textEncoder.encode(serverName),
			serverNameList = tlsBytes(0, uint16be(serverNameBytes.length), serverNameBytes);
		extensions.push(tlsBytes(uint16be(EXT_SERVER_NAME), uint16be(serverNameList.length + 2), uint16be(serverNameList.length), serverNameList))
	}
	extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0, 2, 1, 0)), extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0, 6, 0, 4, 0, 29, 0, 23));
	const signatureBytes = tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
	extensions.push(tlsBytes(uint16be(EXT_SIGNATURE_ALGORITHMS), uint16be(signatureBytes.length + 2), uint16be(signatureBytes.length), signatureBytes));
	const protocols = Array.isArray(alpn) ? alpn.filter(Boolean) : alpn ? [alpn] : [];
	if (protocols.length) {
		const alpnBytes = concatBytes(...protocols.map((protocol => { const protocolBytes = textEncoder.encode(protocol); return tlsBytes(protocolBytes.length, protocolBytes) })));
		extensions.push(tlsBytes(uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION), uint16be(alpnBytes.length + 2), uint16be(alpnBytes.length), alpnBytes))
	}
	if (enableTls13 && keyShares) {
		let keyShareBytes: Uint8Array;
		extensions.push(enableTls12 ? tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 5, 4, 3, 4, 3, 3) : tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 3, 2, 3, 4));
		extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0, 2, 1, 1));
		const ks = keyShares instanceof Uint8Array ? null : keyShares;
		if (ks && ks.x25519 && ks.p256) {
			keyShareBytes = concatBytes(tlsBytes(0, 29, uint16be(ks.x25519.length), ks.x25519), tlsBytes(0, 23, uint16be(ks.p256.length), ks.p256));
		} else if (ks && ks.x25519) {
			keyShareBytes = tlsBytes(0, 29, uint16be(ks.x25519.length), ks.x25519);
		} else if (ks && ks.p256) {
			keyShareBytes = tlsBytes(0, 23, uint16be(ks.p256.length), ks.p256);
		} else {
			if (!(keyShares instanceof Uint8Array)) throw new Error("Invalid keyShares");
			keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.length), keyShares);
		}
		extensions.push(tlsBytes(uint16be(EXT_KEY_SHARE), uint16be(keyShareBytes.length + 2), uint16be(keyShareBytes.length), keyShareBytes))
	}
	const extensionsBytes = concatBytes(...extensions);
	return buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_HELLO, tlsBytes(uint16be(TLS_VERSION_12), clientRandom, 0, uint16be(cipherBytes.length), cipherBytes, 1, 0, uint16be(extensionsBytes.length), extensionsBytes))
}
