/**
 * 自研 TLS 客户端（TLS 1.2/1.3 握手状态机 + 记录加解密，原 _worker.js TlsClient L3711-4051，行为等价移植）。
 *
 * 使用方：HTTPS 链式代理的自研 TLS 分支（代理主机为 IP 时 fetcher 无法带 SNI 转发）
 * 与 admin/check 健康检查。握手经 acceptCertificate 记录叶子证书（sawCert，缺失即报错），不校验证书链。
 */
import { toUint8Array } from '../../utils/bytes';
import {
  aesGcmDecryptWithKey,
  aesGcmEncryptWithKey,
  chacha20Poly1305Decrypt,
  chacha20Poly1305Encrypt,
  constantTimeEqual,
  deriveSharedSecret,
  digestBytes,
  EMPTY_BYTES,
  generateKeyShare,
  hashByteLength,
  hkdfExpandLabel,
  hkdfExtract,
  hmac,
  importAesGcmKey,
  tls12Prf,
} from './primitives';
import {
  ALERT_CLOSE_NOTIFY,
  buildClientHello,
  buildHandshakeMessage,
  buildTlsRecord,
  CONTENT_TYPE_ALERT,
  CONTENT_TYPE_APPLICATION_DATA,
  CONTENT_TYPE_CHANGE_CIPHER_SPEC,
  CONTENT_TYPE_HANDSHAKE,
  CIPHER_SUITES_BY_ID,
  EXT_KEY_SHARE,
  extractLeafCertificate,
  GROUPS_BY_ID,
  HANDSHAKE_TYPE_CERTIFICATE,
  HANDSHAKE_TYPE_CERTIFICATE_REQUEST,
  HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
  HANDSHAKE_TYPE_CLIENT_HELLO,
  HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS,
  HANDSHAKE_TYPE_FINISHED,
  HANDSHAKE_TYPE_KEY_UPDATE,
  HANDSHAKE_TYPE_NEW_SESSION_TICKET,
  HANDSHAKE_TYPE_SERVER_HELLO,
  HANDSHAKE_TYPE_SERVER_HELLO_DONE,
  HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE,
  HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
  parseEncryptedExtensions,
  parseServerHello,
  parseServerKeyExchange,
  readUint16,
  readUint24,
  shouldIgnoreTlsAlert,
  TLS_MAX_PLAINTEXT_FRAGMENT,
  TLS_VERSION_10,
  TLS_VERSION_12,
  TLS_VERSION_13,
  tlsBytes,
  TlsHandshakeParser,
  TlsRecordParser,
} from './records';

export interface TlsClientOptions {
  serverName?: string;
  tls13?: boolean;
  tls12?: boolean;
  alpn?: string | string[] | null;
  allowChacha?: boolean;
  timeout?: number;
  insecure?: boolean;
}

export interface TlsSocketLike {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  close?(): void;
}

const textEncoder = new TextEncoder();

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
const uint16be = (value: number): number[] => [(value >> 8) & 255, value & 255];
const uint64be = (sequenceNumber: bigint): Uint8Array => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, sequenceNumber, false);
  return bytes;
};
const xorSequenceIntoIv = (initializationVector: Uint8Array, sequenceNumber: bigint): Uint8Array => {
  const nonce = initializationVector.slice();
  const sequenceBytes = uint64be(sequenceNumber);
  for (let index = 0; index < 8; index++) nonce[nonce.length - 8 + index]! ^= sequenceBytes[index]!;
  return nonce;
};
const deriveTrafficKeys = (
  hash: string,
  secret: Uint8Array,
  keyLen: number,
  ivLen: number,
): Promise<[Uint8Array, Uint8Array]> =>
  Promise.all([
    hkdfExpandLabel(hash, secret, 'key', EMPTY_BYTES, keyLen),
    hkdfExpandLabel(hash, secret, 'iv', EMPTY_BYTES, ivLen),
  ]) as Promise<[Uint8Array, Uint8Array]>;

export class TlsClient {
	// —— 握手配置与状态字段 ——
	private socket: TlsSocketLike;
	private serverName: string;
	private supportTls13: boolean;
	private supportTls12: boolean;
	private alpnProtocols: string[] | null;
	private allowChacha: boolean;
	private timeout: number;
	private clientRandom: Uint8Array;
	private serverRandom: Uint8Array | null;
	private handshakeChunks: Uint8Array[];
	handshakeComplete = false;
	negotiatedAlpn: string | null = null;
	cipherSuite: number | null = null;
	cipherConfig: { id: number; keyLen: number; ivLen: number; hash: string; tls13?: boolean; chacha?: boolean; kex?: string } | null = null;
	isTls13 = false;
	private masterSecret: Uint8Array | null;
	private handshakeSecret: Uint8Array | null;
	private clientWriteKey: Uint8Array | null;
	private serverWriteKey: Uint8Array | null;
	private clientWriteIv: Uint8Array | null;
	private serverWriteIv: Uint8Array | null;
	private clientHandshakeKey: Uint8Array | null;
	private serverHandshakeKey: Uint8Array | null;
	private clientHandshakeIv: Uint8Array | null;
	private serverHandshakeIv: Uint8Array | null;
	private clientAppKey: Uint8Array | null;
	private serverAppKey: Uint8Array | null;
	private clientAppIv: Uint8Array | null;
	private serverAppIv: Uint8Array | null;
	private clientWriteCryptoKey: CryptoKey | null;
	private serverWriteCryptoKey: CryptoKey | null;
	private clientHandshakeCryptoKey: CryptoKey | null;
	private serverHandshakeCryptoKey: CryptoKey | null;
	private clientAppCryptoKey: CryptoKey | null;
	private serverAppCryptoKey: CryptoKey | null;
	private clientSeqNum = 0n;
	private serverSeqNum = 0n;
	private recordParser: TlsRecordParser;
	private handshakeParser: TlsHandshakeParser;
	private keyPairs: Map<number, { keyPair: CryptoKeyPair; publicKeyRaw: Uint8Array }>;
	private ecdhKeyPair: CryptoKeyPair | null;
	private sawCert = false;
	constructor(socket: TlsSocketLike, options: TlsClientOptions = {}) {
		this.socket = socket;
		this.serverName = options.serverName || '';
		this.supportTls13 = options.tls13 !== false;
		this.supportTls12 = options.tls12 !== false;
		if (!this.supportTls13 && !this.supportTls12) throw new Error('At least one TLS version must be enabled');
		this.alpnProtocols = Array.isArray(options.alpn) ? options.alpn : options.alpn ? [options.alpn] : null;
		this.allowChacha = options.allowChacha !== false;
		this.timeout = options.timeout ?? 30000;
		this.clientRandom = crypto.getRandomValues(new Uint8Array(32));
		this.serverRandom = null;
		this.handshakeChunks = [];
		this.handshakeComplete = false;
		this.negotiatedAlpn = null;
		this.cipherSuite = null;
		this.cipherConfig = null;
		this.isTls13 = false;
		this.masterSecret = null;
		this.handshakeSecret = null;
		this.clientWriteKey = null;
		this.serverWriteKey = null;
		this.clientWriteIv = null;
		this.serverWriteIv = null;
		this.clientHandshakeKey = null;
		this.serverHandshakeKey = null;
		this.clientHandshakeIv = null;
		this.serverHandshakeIv = null;
		this.clientAppKey = null;
		this.serverAppKey = null;
		this.clientAppIv = null;
		this.serverAppIv = null;
		this.clientWriteCryptoKey = null;
		this.serverWriteCryptoKey = null;
		this.clientHandshakeCryptoKey = null;
		this.serverHandshakeCryptoKey = null;
		this.clientAppCryptoKey = null;
		this.serverAppCryptoKey = null;
		this.clientSeqNum = 0n;
		this.serverSeqNum = 0n;
		this.recordParser = new TlsRecordParser();
		this.handshakeParser = new TlsHandshakeParser();
		this.keyPairs = new Map();
		this.ecdhKeyPair = null;
		this.sawCert = false;
	}

	recordHandshake(chunk: Uint8Array): void { this.handshakeChunks.push(chunk) }
	transcript(): Uint8Array { return this.handshakeChunks.length === 1 ? this.handshakeChunks[0]! : concatBytes(...this.handshakeChunks) }
	getCipherConfig(cipherSuite: number | null) { return cipherSuite === null ? null : CIPHER_SUITES_BY_ID.get(cipherSuite) ?? null }
	async readChunk(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<ReadableStreamReadResult<Uint8Array>> { return this.timeout ? Promise.race([reader.read(), new Promise<ReadableStreamReadResult<Uint8Array>>((_, reject) => { setTimeout(() => reject(new Error('TLS read timeout')), this.timeout); })]) : reader.read(); }
	async readRecordsUntil(reader: ReadableStreamDefaultReader<Uint8Array>, predicate: (record: { type: number; fragment: Uint8Array }) => Promise<unknown>, closedError: string): Promise<void> {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();)
				if (await predicate(record)) return;
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error(closedError);
			this.recordParser.feed(value)
		}
	}
	async readHandshakeUntil(reader: ReadableStreamDefaultReader<Uint8Array>, predicate: (message: { type: number; body: Uint8Array; raw: Uint8Array }) => Promise<unknown>, closedError: string): Promise<void> {
		for (let message; message = this.handshakeParser.next();)
			if (await predicate(message)) return;
		return this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(record.fragment);
				for (let message; message = this.handshakeParser.next();)
					if (await predicate(message)) return 1
			}
		}), closedError)
	}
	async acceptCertificate(certificate: Uint8Array | null): Promise<void> { if (!certificate?.length) throw new Error("Empty certificate"); this.sawCert = true }
	async handshake(): Promise<void> {
		const [p256Share, x25519Share] = await Promise.all([generateKeyShare("P-256"), generateKeyShare("X25519")]);
		this.keyPairs = new Map([[23, p256Share], [29, x25519Share]]), this.ecdhKeyPair = p256Share.keyPair;
		const reader = this.socket.readable.getReader(),
			writer = this.socket.writable.getWriter();
		try {
			const clientHello = buildClientHello(this.clientRandom, this.serverName, { x25519: x25519Share.publicKeyRaw, p256: p256Share.publicKeyRaw }, { tls13: this.supportTls13, tls12: this.supportTls12, alpn: this.alpnProtocols, chacha: this.allowChacha });
			this.recordHandshake(clientHello), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10));
			const serverHello = await this.receiveServerHello(reader);
			if (serverHello.isHRR) throw new Error("HelloRetryRequest is not supported by TLSClientMini");
			if (serverHello.keyShare?.group !== undefined && this.keyPairs.has(serverHello.keyShare.group)) {
				const selectedKeyPair = this.keyPairs.get(serverHello.keyShare.group);
				if (selectedKeyPair) this.ecdhKeyPair = selectedKeyPair.keyPair
			}
			serverHello.isTls13 ? await this.handshakeTls13(reader, writer, serverHello) : await this.handshakeTls12(reader, writer), this.handshakeComplete = true
		} finally {
			reader.releaseLock(), writer.releaseLock()
		}
	}
	async receiveServerHello(reader: ReadableStreamDefaultReader<Uint8Array>) {
		for (; ;) {
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error("Connection closed waiting for ServerHello");
			let record;
			for (this.recordParser.feed(value); record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (shouldIgnoreTlsAlert(record.fragment)) continue;
					throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
				}
				if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(record.fragment); message = this.handshakeParser.next();) {
					if (message.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
					this.recordHandshake(message.raw);
					const serverHello = parseServerHello(message.body);
					if (this.serverRandom = serverHello.serverRandom, this.cipherSuite = serverHello.cipherSuite, this.cipherConfig = this.getCipherConfig(serverHello.cipherSuite), this.isTls13 = serverHello.isTls13, this.negotiatedAlpn = serverHello.alpn || null, !this.cipherConfig) throw new Error(`Unsupported cipher suite: 0x${serverHello.cipherSuite.toString(16)}`);
					return serverHello
				}
			}
		}
	}
	async handshakeTls12(reader: ReadableStreamDefaultReader<Uint8Array>, writer: WritableStreamDefaultWriter<Uint8Array>): Promise<void> {
		/** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */
		let serverKeyExchange: { namedCurve: number; serverPublicKey: Uint8Array } | null = null;
		let sawServerHelloDone = false;
		let clientCertRequested = false;
		if (await this.readHandshakeUntil(reader, (async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_CERTIFICATE: {
					this.recordHandshake(message.raw);
					const certificate = extractLeafCertificate(message.body, 1);
					if (!certificate) throw new Error("Missing TLS 1.2 certificate");
					await this.acceptCertificate(certificate);
					break
				}
				case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
					this.recordHandshake(message.raw), serverKeyExchange = parseServerKeyExchange(message.body);
					break;
				case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
					return this.recordHandshake(message.raw), sawServerHelloDone = true, 1;
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					this.recordHandshake(message.raw), clientCertRequested = true;
					break;
				default:
					this.recordHandshake(message.raw)
			}
		}), "Connection closed during TLS 1.2 handshake"), !this.sawCert) throw new Error("Missing TLS 1.2 leaf certificate");
		const serverKeyExchangeData = serverKeyExchange as { namedCurve: number; serverPublicKey: Uint8Array } | null;
		if (!serverKeyExchangeData) throw new Error("Missing TLS 1.2 ServerKeyExchange");
		const curveName = GROUPS_BY_ID.get(serverKeyExchangeData.namedCurve);
		if (!curveName) throw new Error(`Unsupported named curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const keyShare = this.keyPairs.get(serverKeyExchangeData.namedCurve);
		if (!keyShare) throw new Error(`Missing key pair for curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const preMasterSecret = await deriveSharedSecret(keyShare.keyPair.privateKey, serverKeyExchangeData.serverPublicKey, curveName),
			clientKeyExchange = buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, tlsBytes(keyShare.publicKeyRaw.length, keyShare.publicKeyRaw));
		if (clientCertRequested) {
			const emptyCertificate = buildHandshakeMessage(HANDSHAKE_TYPE_CERTIFICATE, tlsBytes(0, 0, 0));
			this.recordHandshake(emptyCertificate), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, emptyCertificate))
		}
		this.recordHandshake(clientKeyExchange);
		const hashName = this.cipherConfig!.hash;
		this.masterSecret = await tls12Prf(preMasterSecret, "master secret", concatBytes(this.clientRandom, this.serverRandom), 48, hashName);
		const keyLen = this.cipherConfig!.keyLen,
			ivLen = this.cipherConfig!.ivLen,
			keyBlock = await tls12Prf(this.masterSecret!, "key expansion", concatBytes(this.serverRandom, this.clientRandom), 2 * keyLen + 2 * ivLen, hashName);
		this.clientWriteKey = keyBlock.slice(0, keyLen), this.serverWriteKey = keyBlock.slice(keyLen, 2 * keyLen), this.clientWriteIv = keyBlock.slice(2 * keyLen, 2 * keyLen + ivLen), this.serverWriteIv = keyBlock.slice(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
		if (!this.cipherConfig!.chacha) [this.clientWriteCryptoKey, this.serverWriteCryptoKey] = await Promise.all([importAesGcmKey(this.clientWriteKey!, ["encrypt"]), importAesGcmKey(this.serverWriteKey!, ["decrypt"])]);
		await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientKeyExchange)), await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(1)));
		const clientVerifyData = await tls12Prf(this.masterSecret!, "client finished", await digestBytes(hashName, this.transcript()), 12, hashName),
			finishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerifyData);
		this.recordHandshake(finishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, await this.encryptTls12(finishedMessage, CONTENT_TYPE_HANDSHAKE)));
		let sawChangeCipherSpec = false;
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) return void (sawChangeCipherSpec = true);
			if (record.type !== CONTENT_TYPE_HANDSHAKE || !sawChangeCipherSpec) return;
			const decrypted = await this.decryptTls12(record.fragment, CONTENT_TYPE_HANDSHAKE);
			if (decrypted[0] !== HANDSHAKE_TYPE_FINISHED) return;
			const verifyLength = readUint24(decrypted, 1),
				verifyData = decrypted.slice(4, 4 + verifyLength),
				expectedVerifyData = await tls12Prf(this.masterSecret!, "server finished", await digestBytes(hashName, this.transcript()), 12, hashName);
			if (!constantTimeEqual(verifyData, expectedVerifyData)) throw new Error("TLS 1.2 server Finished verify failed");
			return 1
		}), "Connection closed waiting for TLS 1.2 Finished")
	}
	async handshakeTls13(reader: ReadableStreamDefaultReader<Uint8Array>, writer: WritableStreamDefaultWriter<Uint8Array>, serverHello: ReturnType<typeof parseServerHello>): Promise<void> {
		const groupName = serverHello.keyShare?.group !== undefined ? GROUPS_BY_ID.get(serverHello.keyShare.group) : undefined;
		if (!groupName || !serverHello.keyShare?.key?.length) throw new Error("Missing TLS 1.3 key_share");
		const hashName = this.cipherConfig!.hash,
			hashLen = hashByteLength(hashName),
			keyLen = this.cipherConfig!.keyLen,
			ivLen = this.cipherConfig!.ivLen,
			sharedSecret = await deriveSharedSecret(this.ecdhKeyPair!.privateKey, serverHello.keyShare.key, groupName),
			earlySecret = await hkdfExtract(hashName, null, new Uint8Array(hashLen)),
			derivedSecret = await hkdfExpandLabel(hashName, earlySecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen);
		this.handshakeSecret = await hkdfExtract(hashName, derivedSecret, sharedSecret);
		const transcriptHash = await digestBytes(hashName, this.transcript()),
			clientHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret!, "c hs traffic", transcriptHash, hashLen),
			serverHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret!, "s hs traffic", transcriptHash, hashLen);
		[this.clientHandshakeKey!, this.clientHandshakeIv!] = await deriveTrafficKeys(hashName, clientHandshakeTrafficSecret, keyLen, ivLen), [this.serverHandshakeKey!, this.serverHandshakeIv!] = await deriveTrafficKeys(hashName, serverHandshakeTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig!.chacha) [this.clientHandshakeCryptoKey, this.serverHandshakeCryptoKey] = await Promise.all([importAesGcmKey(this.clientHandshakeKey!, ["encrypt"]), importAesGcmKey(this.serverHandshakeKey!, ["decrypt"])]);
		const serverFinishedKey = await hkdfExpandLabel(hashName, serverHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen);
		let serverFinishedReceived = false;
		let clientCertRequested = false;
		const handleHandshakeMessage = async (message: { type: number; body: Uint8Array; raw: Uint8Array }) => {
			switch (message.type) {
				case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: {
					const encryptedExtensions = parseEncryptedExtensions(message.body);
					encryptedExtensions.alpn && (this.negotiatedAlpn = encryptedExtensions.alpn), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE: {
					const certificate = extractLeafCertificate(message.body);
					if (!certificate) throw new Error("Missing TLS 1.3 certificate");
					await this.acceptCertificate(certificate), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					this.recordHandshake(message.raw), clientCertRequested = true;
					break;
				case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
					this.recordHandshake(message.raw);
					break;
				case HANDSHAKE_TYPE_FINISHED: {
					const expectedVerifyData = await hmac(hashName, serverFinishedKey, await digestBytes(hashName, this.transcript()));
					if (!constantTimeEqual(expectedVerifyData, message.body)) throw new Error("TLS 1.3 server Finished verify failed");
					this.recordHandshake(message.raw), serverFinishedReceived = true;
					break
				}
				default:
					this.recordHandshake(message.raw)
			}
		};
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC || record.type === CONTENT_TYPE_HANDSHAKE) return;
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type !== CONTENT_TYPE_APPLICATION_DATA) return;
			const decrypted = await this.decryptTls13Handshake(record.fragment),
				innerType = decrypted[decrypted.length - 1],
				plaintext = decrypted.slice(0, -1);
			if (innerType === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(plaintext);
				for (let message; message = this.handshakeParser.next();)
					if (await handleHandshakeMessage(message), serverFinishedReceived) return 1
			}
		}), "Connection closed during TLS 1.3 handshake");
		const applicationTranscriptHash = await digestBytes(hashName, this.transcript()),
			masterDerivedSecret = await hkdfExpandLabel(hashName, this.handshakeSecret!, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen),
			masterSecret = await hkdfExtract(hashName, masterDerivedSecret, new Uint8Array(hashLen)),
			clientAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "c ap traffic", applicationTranscriptHash, hashLen),
			serverAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "s ap traffic", applicationTranscriptHash, hashLen);
		[this.clientAppKey!, this.clientAppIv!] = await deriveTrafficKeys(hashName, clientAppTrafficSecret, keyLen, ivLen), [this.serverAppKey!, this.serverAppIv!] = await deriveTrafficKeys(hashName, serverAppTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig!.chacha) [this.clientAppCryptoKey, this.serverAppCryptoKey] = await Promise.all([importAesGcmKey(this.clientAppKey!, ["encrypt"]), importAesGcmKey(this.serverAppKey!, ["decrypt"])]);
		let clientFlightHandshake: Uint8Array = EMPTY_BYTES;
		if (clientCertRequested) clientFlightHandshake = buildHandshakeMessage(HANDSHAKE_TYPE_CERTIFICATE, tlsBytes(0, 0, 0, 0)), this.recordHandshake(clientFlightHandshake);
		const clientFinishedKey = await hkdfExpandLabel(hashName, clientHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen),
			clientFinishedVerifyData = await hmac(hashName, clientFinishedKey, await digestBytes(hashName, this.transcript())),
			clientFinishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientFinishedVerifyData);
		this.recordHandshake(clientFinishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, await this.encryptTls13Handshake(concatBytes(clientFlightHandshake, clientFinishedMessage, [CONTENT_TYPE_HANDSHAKE])))), this.clientSeqNum = 0n, this.serverSeqNum = 0n
	}
	async encryptTls12(plaintext: Uint8Array, contentType: number): Promise<Uint8Array> {
		const sequenceNumber = this.clientSeqNum++,
			sequenceBytes = uint64be(sequenceNumber),
			additionalData = concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(plaintext.length));
		if (this.cipherConfig!.chacha) {
			const nonce = xorSequenceIntoIv(this.clientWriteIv!, sequenceNumber);
			return chacha20Poly1305Encrypt(this.clientWriteKey!, nonce, plaintext, additionalData)
		}
		const explicitNonce = crypto.getRandomValues(new Uint8Array(8));
		if (!this.clientWriteCryptoKey) this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey!, ["encrypt"]);
		return concatBytes(explicitNonce, await aesGcmEncryptWithKey(this.clientWriteCryptoKey, concatBytes(this.clientWriteIv!, explicitNonce), plaintext, additionalData))
	}
	async decryptTls12(ciphertext: Uint8Array, contentType: number): Promise<Uint8Array> {
		const sequenceNumber = this.serverSeqNum++,
			sequenceBytes = uint64be(sequenceNumber);
		if (this.cipherConfig!.chacha) {
			const nonce = xorSequenceIntoIv(this.serverWriteIv!, sequenceNumber);
			return chacha20Poly1305Decrypt(this.serverWriteKey!, nonce, ciphertext, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(ciphertext.length - 16)))
		}
		const explicitNonce = ciphertext.subarray(0, 8),
			encryptedData = ciphertext.subarray(8);
		if (!this.serverWriteCryptoKey) this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey!, ["decrypt"]);
		return aesGcmDecryptWithKey(this.serverWriteCryptoKey, concatBytes(this.serverWriteIv!, explicitNonce), encryptedData, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(encryptedData.length - 16)))
	}
	async encryptTls13Handshake(plaintext: Uint8Array): Promise<Uint8Array> {
		const nonce = xorSequenceIntoIv(this.clientHandshakeIv!, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig!.chacha) return chacha20Poly1305Encrypt(this.clientHandshakeKey!, nonce, plaintext, additionalData);
		if (!this.clientHandshakeCryptoKey) this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey!, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientHandshakeCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13Handshake(ciphertext: Uint8Array): Promise<Uint8Array> {
		const nonce = xorSequenceIntoIv(this.serverHandshakeIv!, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length));
		const decrypted = this.cipherConfig!.chacha ? await chacha20Poly1305Decrypt(this.serverHandshakeKey!, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverHandshakeCryptoKey || (this.serverHandshakeCryptoKey = await importAesGcmKey(this.serverHandshakeKey!, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = decrypted.length - 1;
		for (; innerTypeIndex >= 0 && !decrypted[innerTypeIndex];) innerTypeIndex--;
		return innerTypeIndex < 0 ? EMPTY_BYTES : decrypted.slice(0, innerTypeIndex + 1)
	}
	async encryptTls13(data: Uint8Array): Promise<Uint8Array> {
		const plaintext = concatBytes(data, [CONTENT_TYPE_APPLICATION_DATA]),
			nonce = xorSequenceIntoIv(this.clientAppIv!, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig!.chacha) return chacha20Poly1305Encrypt(this.clientAppKey!, nonce, plaintext, additionalData);
		if (!this.clientAppCryptoKey) this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey!, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientAppCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13(ciphertext: Uint8Array): Promise<{ data: Uint8Array; type: number }> {
		const nonce = xorSequenceIntoIv(this.serverAppIv!, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length)),
			plaintext = this.cipherConfig!.chacha ? await chacha20Poly1305Decrypt(this.serverAppKey!, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverAppCryptoKey || (this.serverAppCryptoKey = await importAesGcmKey(this.serverAppKey!, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = plaintext.length - 1;
		for (; innerTypeIndex >= 0 && !plaintext[innerTypeIndex];) innerTypeIndex--;
		if (innerTypeIndex < 0) return {
			data: EMPTY_BYTES,
			type: 0
		};
		return {
			data: plaintext.slice(0, innerTypeIndex),
			type: plaintext[innerTypeIndex]!
		}
	}
	async write(data: Uint8Array | ArrayBuffer | ArrayBufferView): Promise<void> {
		if (!this.handshakeComplete) throw new Error("Handshake not complete");
		const plaintext = toUint8Array(data);
		if (!plaintext.byteLength) return;
		const writer = this.socket.writable.getWriter();
		try {
			const records = [];
			for (let offset = 0; offset < plaintext.byteLength; offset += TLS_MAX_PLAINTEXT_FRAGMENT) {
				const chunk = plaintext.subarray(offset, Math.min(offset + TLS_MAX_PLAINTEXT_FRAGMENT, plaintext.byteLength));
				const encrypted = this.isTls13 ? await this.encryptTls13(chunk) : await this.encryptTls12(chunk, CONTENT_TYPE_APPLICATION_DATA);
				records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
			}
			await writer.write(records.length === 1 ? records[0]! : concatBytes(...records))
		} finally {
			writer.releaseLock()
		}
	}
	async read(): Promise<Uint8Array | null> {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${record.fragment[1]}`)
				}
				if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;
				if (!this.isTls13) return this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
				const { data, type } = await this.decryptTls13(record.fragment);
				if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
				if (type === CONTENT_TYPE_ALERT) {
					if (data[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${data[1]}`)
				}
				if (type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(data); message = this.handshakeParser.next();)
					if (message.type !== HANDSHAKE_TYPE_NEW_SESSION_TICKET && message.type === HANDSHAKE_TYPE_KEY_UPDATE) throw new Error("TLS 1.3 KeyUpdate is not supported by TLSClientMini")
			}
			const reader = this.socket.readable.getReader();
			try {
				const { value, done } = await this.readChunk(reader);
				if (done) return null;
				this.recordParser.feed(value)
			} finally {
				reader.releaseLock()
			}
		}
	}
	close(): void { this.socket.close?.(); }
}
