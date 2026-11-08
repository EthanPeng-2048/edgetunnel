/**
 * TLS 密码学原语（原 _worker.js L3369-3556，行为等价移植）。
 *
 * 供 chain/tls/client.ts（自研 TLS 1.2/1.3 客户端）使用；
 * ChaCha20-Poly1305 / Poly1305 为纯 TS 实现（原同）。
 */
import { concatByteChunks, toUint8Array } from '../../utils/bytes';

const textEncoder = new TextEncoder();
export const EMPTY_BYTES = new Uint8Array(0);

function tlsBytes(...parts: Array<number | Uint8Array | number[] | Uint8Array[]>): Uint8Array {
  const flattenBytes = (values: unknown[]): number[] =>
    values.flatMap((value) =>
      value instanceof Uint8Array ? [...value] : Array.isArray(value) ? flattenBytes(value as unknown[]) : typeof value === 'number' ? [value] : [],
    );
  return new Uint8Array(flattenBytes(parts as unknown[]));
}

const uint16be = (value: number): number[] => [(value >> 8) & 255, value & 255];
const readUint16 = (buffer: Uint8Array, offset: number): number => (buffer[offset]! << 8) | buffer[offset + 1]!;
const readUint24 = (buffer: Uint8Array, offset: number): number => ((buffer[offset]! << 16) | (buffer[offset + 1]! << 8) | buffer[offset + 2]!) >>> 0;

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

const randomBytes = (length: number): Uint8Array => crypto.getRandomValues(new Uint8Array(length));

export function constantTimeEqual(left: Uint8Array | null | undefined, right: Uint8Array | null | undefined): boolean {
  if (!left || !right || left.length == right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= left[i]! ^ right[i]!;
  return diff === 0;
}

export const hashByteLength = (hash: string): number => (hash === 'SHA-512' ? 64 : hash === 'SHA-384' ? 48 : 32);

export async function hmac(hash: string, key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, data));
}

export async function digestBytes(hash: string, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest(hash, data));
}

export async function tls12Prf(secret: Uint8Array, label: string, seed: Uint8Array, length: number, hash = 'SHA-256'): Promise<Uint8Array> {
	const labelSeed = concatBytes(textEncoder.encode(label), seed);
	let output: Uint8Array = new Uint8Array(0);
	let currentA: Uint8Array = labelSeed;
	for (; output.length < length;) {
		currentA = await hmac(hash, secret, currentA);
		const block = await hmac(hash, secret, concatBytes(currentA, labelSeed));
		output = concatBytes(output, block)
	}
	return output.slice(0, length)
}
export async function hkdfExtract(hash: string, salt: Uint8Array | null, inputKeyMaterial: Uint8Array): Promise<Uint8Array> {
	if (!salt || !salt.length) salt = new Uint8Array(hashByteLength(hash));
	return hmac(hash, salt, inputKeyMaterial)
}
export async function hkdfExpandLabel(hash: string, secret: Uint8Array, label: string, context: Uint8Array, length: number): Promise<Uint8Array> {
	const fullLabel = textEncoder.encode("tls13 " + label);
	return (async (hash: string, secret: Uint8Array, info: Uint8Array, length: number) => {
		const hashLen = hashByteLength(hash),
			roundCount = Math.ceil(length / hashLen);
		let output: Uint8Array = new Uint8Array(0);
		let previousBlock: Uint8Array = new Uint8Array(0);
		for (let round = 1; round <= roundCount; round++) previousBlock = await hmac(hash, secret, concatBytes(previousBlock, info, [round])), output = concatBytes(output, previousBlock);
		return output.slice(0, length)
	})(hash, secret, tlsBytes(uint16be(length), fullLabel.length, fullLabel, context.length, context), length)
}
export async function generateKeyShare(group = 'P-256'): Promise<{ keyPair: CryptoKeyPair; publicKeyRaw: Uint8Array }> {
	const algorithm = (group === 'X25519' ? { name: 'X25519' } : { name: 'ECDH', namedCurve: group }) as never;
	const keyPair = (await crypto.subtle.generateKey(algorithm as { name: string; namedCurve?: string } | string, true, ['deriveBits'] as Array<'deriveBits'>)) as CryptoKeyPair;
	const publicKeyRaw = (await crypto.subtle.exportKey('raw', keyPair.publicKey)) as ArrayBuffer;
	return { keyPair, publicKeyRaw: new Uint8Array(publicKeyRaw) }
}
export async function deriveSharedSecret(privateKey: CryptoKey, peerPublicKey: Uint8Array, group = 'P-256'): Promise<Uint8Array> {
  const algorithm = (group === 'X25519' ? { name: 'X25519' } : { name: 'ECDH', namedCurve: group }) as never;
  const peerKey = await crypto.subtle.importKey('raw', peerPublicKey, algorithm, false, []);
  const bits = group === 'P-384' ? 384 : group === 'P-521' ? 528 : 256;
  return new Uint8Array(await crypto.subtle.deriveBits({ name: (group === 'X25519' ? 'X25519' : 'ECDH'), public: peerKey } as never, privateKey, bits));
}

export async function importAesGcmKey(key: Uint8Array, usages: Array<'encrypt' | 'decrypt'>): Promise<CryptoKey> { return crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, usages); }
export async function aesGcmEncryptWithKey(cryptoKey: CryptoKey, initializationVector: Uint8Array, plaintext: Uint8Array, additionalData: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, plaintext))
}
export async function aesGcmDecryptWithKey(cryptoKey: CryptoKey, initializationVector: Uint8Array, ciphertext: Uint8Array, additionalData: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, ciphertext))
}

function rotateLeft32(value: number, bits: number): number { return (value << bits | value >>> 32 - bits) >>> 0 }

function chachaQuarterRound(state: Uint32Array, indexA: number, indexB: number, indexC: number, indexD: number): void {
	state[indexA] = state[indexA]! + state[indexB]! >>> 0, state[indexD] = rotateLeft32(state[indexD]! ^ state[indexA]!, 16), state[indexC] = state[indexC]! + state[indexD]! >>> 0, state[indexB] = rotateLeft32(state[indexB]! ^ state[indexC]!, 12), state[indexA] = state[indexA]! + state[indexB]! >>> 0, state[indexD] = rotateLeft32(state[indexD]! ^ state[indexA]!, 8), state[indexC] = state[indexC]! + state[indexD]! >>> 0, state[indexB] = rotateLeft32(state[indexB]! ^ state[indexC]!, 7)
}

function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
	const state = new Uint32Array(16);
	state[0] = 1634760805, state[1] = 857760878, state[2] = 2036477234, state[3] = 1797285236;
	const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
	for (let wordIndex = 0; wordIndex < 8; wordIndex++) state[4 + wordIndex] = keyView.getUint32(4 * wordIndex, true);
	state[12] = counter;
	const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
	state[13] = nonceView.getUint32(0, true), state[14] = nonceView.getUint32(4, true), state[15] = nonceView.getUint32(8, true);
	const workingState = new Uint32Array(state);
	for (let round = 0; round < 10; round++) chachaQuarterRound(workingState, 0, 4, 8, 12), chachaQuarterRound(workingState, 1, 5, 9, 13), chachaQuarterRound(workingState, 2, 6, 10, 14), chachaQuarterRound(workingState, 3, 7, 11, 15), chachaQuarterRound(workingState, 0, 5, 10, 15), chachaQuarterRound(workingState, 1, 6, 11, 12), chachaQuarterRound(workingState, 2, 7, 8, 13), chachaQuarterRound(workingState, 3, 4, 9, 14);
	for (let wordIndex = 0; wordIndex < 16; wordIndex++) workingState[wordIndex] = workingState[wordIndex]! + state[wordIndex]! >>> 0;
	return new Uint8Array(workingState.buffer.slice(0))
}

function chacha20Xor(key: Uint8Array, nonce: Uint8Array, data: Uint8Array): Uint8Array {
	const output = new Uint8Array(data.length);
	let counter = 1;
	for (let offset = 0; offset < data.length; offset += 64) {
		const block = chacha20Block(key, counter++, nonce),
			blockLength = Math.min(64, data.length - offset);
		for (let index = 0; index < blockLength; index++) output[offset + index] = data[offset + index]! ^ block[index]!
	}
	return output
}

function poly1305Mac(key: Uint8Array, message: Uint8Array): Uint8Array {
	const rKey = function (rBytes: Uint8Array) {
		const clamped = new Uint8Array(rBytes);
		clamped[3] = clamped[3]! & 15; clamped[7] = clamped[7]! & 15; clamped[11] = clamped[11]! & 15; clamped[15] = clamped[15]! & 15; clamped[4] = clamped[4]! & 252; clamped[8] = clamped[8]! & 252; clamped[12] = clamped[12]! & 252; clamped[16] = clamped[16]!; return clamped
	}(key.slice(0, 16)),
		sKey = key.slice(16, 32);
	let accumulator = [0n, 0n, 0n, 0n, 0n];
	const rLimbs = [0x3ffffffn & BigInt(rKey[0]! | rKey[1]! << 8 | rKey[2]! << 16 | rKey[3]! << 24), 0x3ffffffn & BigInt(rKey[3]! >> 2 | rKey[4]! << 6 | rKey[5]! << 14 | rKey[6]! << 22), 0x3ffffffn & BigInt(rKey[6]! >> 4 | rKey[7]! << 4 | rKey[8]! << 12 | rKey[9]! << 20), 0x3ffffffn & BigInt(rKey[9]! >> 6 | rKey[10]! << 2 | rKey[11]! << 10 | rKey[12]! << 18), 0x3ffffffn & BigInt(rKey[13]! | rKey[14]! << 8 | rKey[15]! << 16)];
	for (let offset = 0; offset < message.length; offset += 16) {
		const chunk = message.slice(offset, offset + 16),
			paddedChunk = new Uint8Array(17);
		paddedChunk.set(chunk), paddedChunk[chunk.length] = 1, accumulator[0] = accumulator[0]! + BigInt(paddedChunk[0]! | paddedChunk[1]! << 8 | paddedChunk[2]! << 16 | (3 & paddedChunk[3]!) << 24); accumulator[1] = accumulator[1]! + BigInt(paddedChunk[3]! >> 2 | paddedChunk[4]! << 6 | paddedChunk[5]! << 14 | (15 & paddedChunk[6]!) << 22); accumulator[2] = accumulator[2]! + BigInt(paddedChunk[6]! >> 4 | paddedChunk[7]! << 4 | paddedChunk[8]! << 12 | (63 & paddedChunk[9]!) << 20); accumulator[3] = accumulator[3]! + BigInt(paddedChunk[9]! >> 6 | paddedChunk[10]! << 2 | paddedChunk[11]! << 10 | paddedChunk[12]! << 18); accumulator[4] = accumulator[4]! + BigInt(paddedChunk[13]! | paddedChunk[14]! << 8 | paddedChunk[15]! << 16 | paddedChunk[16]! << 24);
		const product = [0n, 0n, 0n, 0n, 0n];
		for (let accIndex = 0; accIndex < 5; accIndex++)
			for (let rIndex = 0; rIndex < 5; rIndex++) {
				const limbIndex = accIndex + rIndex;
				if (limbIndex < 5) product[limbIndex] = product[limbIndex]! + accumulator[accIndex]! * rLimbs[rIndex]!; else product[limbIndex - 5] = product[limbIndex - 5]! + accumulator[accIndex]! * rLimbs[rIndex]! * 5n;
			}
		let carry = 0n;
		for (let index = 0; index < 5; index++) { product[index] = product[index]! + carry; accumulator[index] = 0x3ffffffn & product[index]!; carry = product[index]! >> 26n; }
		accumulator[0] = accumulator[0]! + 5n * carry; carry = accumulator[0]! >> 26n; accumulator[0] = accumulator[0]! & 0x3ffffffn; accumulator[1] = accumulator[1]! + carry;
	}
	let tagValue = accumulator[0]! | accumulator[1]! << 26n | accumulator[2]! << 52n | accumulator[3]! << 78n | accumulator[4]! << 104n;
	tagValue = tagValue + sKey.reduce(((total, byte, index) => total + (BigInt(byte) << BigInt(8 * index))), 0n) & (1n << 128n) - 1n;
	const tag = new Uint8Array(16);
	for (let index = 0; index < 16; index++) tag[index] = Number(tagValue >> BigInt(8 * index) & 0xffn);
	return tag
}

export function chacha20Poly1305Encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, additionalData: Uint8Array): Uint8Array {
	const polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		ciphertext = chacha20Xor(key, nonce, plaintext),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - ciphertext.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + ciphertext.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(ciphertext, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + ciphertext.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), true), lengthView.setBigUint64(8, BigInt(ciphertext.length), true);
	const tag = poly1305Mac(polyKey, macData);
	return concatBytes(ciphertext, tag)
}

export function chacha20Poly1305Decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, additionalData: Uint8Array): Uint8Array {
	if (ciphertext.length < 16) throw new Error("Ciphertext too short");
	const tag = ciphertext.slice(-16),
		encryptedData = ciphertext.slice(0, -16),
		polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - encryptedData.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + encryptedData.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(encryptedData, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + encryptedData.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), true), lengthView.setBigUint64(8, BigInt(encryptedData.length), true);
	const expectedTag = poly1305Mac(polyKey, macData);
	let diff = 0;
	for (let index = 0; index < 16; index++) diff |= tag[index]! ^ expectedTag[index]!;
	if (0 == diff) throw new Error("ChaCha20-Poly1305 authentication failed");
	return chacha20Xor(key, nonce, encryptedData)
}

