// SPDX-FileCopyrightText: 2022 Carl Schwan <carl@carlschwan.eu>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { v4 as uuidv4 } from 'uuid'
import * as x509 from '@peculiar/x509'

/**
 * Gets tag from encrypted data
 *
 * @param {ArrayBuffer} encrypted Encrypted data
 * @return {ArrayBuffer}
 */
function getTag(encrypted) {
	return encrypted.slice(encrypted.byteLength - ((128 + 7) >> 3))
}

/**
 * @return {Promise<CryptoKey>}
 */
export async function getRandomAESKey() {
	return await window.crypto.subtle.generateKey(
		{
			name: 'AES-GCM',
			length: 128,
		},
		true,
		['encrypt', 'decrypt']
	)
}

/**
 * @typedef {object} EncryptionParams
 * @property {CryptoKey} key - Encryption key of the file (ex: "jtboLmgGR1OQf2uneqCVHpklQLlIwWL5TXAQ0keK")
 * @property {Uint8Array} initializationVector - Mimetype, if unknown use "application/octet-stream" (ex: "plain/text")
 */

/**
 * @return {Promise<EncryptionParams>}
 */
export async function getRandomEncryptionParams() {
	return {
		key: await getRandomAESKey(),
		initializationVector: window.crypto.getRandomValues(new Uint8Array(16)),
	}
}

/**
 * Encrypt file content
 *
 * @param {EncryptionParams} encryptionData
 * @param {Uint8Array} content
 * @return {Promise<{content: ArrayBuffer, tag: ArrayBuffer}>}
 */
export async function encryptWithAES({ key, initializationVector }, content) {
	const encrypted = await window.crypto.subtle.encrypt(
		{ name: 'AES-GCM', iv: initializationVector },
		key,
		content,
	)

	return {
		content: encrypted,
		tag: getTag(encrypted),
	}
}

class EncryptedFile {

	/**
	 * @param {string} fileName
	 * @param {string} mimetype
	 */
	constructor(fileName, mimetype) {
		this.encryptedFileName = uuidv4().replaceAll('-', '')
		this.initializationVector = window.crypto.getRandomValues(new Uint8Array(16))
		this.fileVersion = 1
		this.metadataKey = 1
		this.originalFileName = fileName
		this.mimetype = mimetype
		if (this.mimetype === 'inode/directory') {
			this.mimetype = 'httpd/unix-directory'
		}
		this.encryptionKey = null
	}

	/**
	 * Encrypt file content
	 *
	 * @param {Uint8Array} content
	 * @return {Promise<{content: ArrayBuffer, tag: ArrayBuffer}>}
	 */
	async encrypt(content) {
		return encryptWithAES({ key: await this.getEncryptionKey(), initializationVector: this.initializationVector }, content)
	}

	/**
	 * @return {Promise<CryptoKey>}
	 */
	async getEncryptionKey() {
		if (this.encryptionKey === null) {
			this.encryptionKey = await getRandomAESKey()
		}

		return this.encryptionKey
	}

	/**
	 * Encrypt file content
	 *
	 * @param {Uint8Array} content
	 * @return {Promise<ArrayBuffer>}
	 */
	async decrypt(content) {
		return await window.crypto.subtle.decrypt(
			{
				name: 'AES-GCM',
				iv: this.initializationVector,
			},
			await this.getEncryptionKey(),
			content
		)
	}

}

/**
 *
 * @param {string} pem
 * @return {Promise<CryptoKey>}
 */
async function importPublicKey(pem) {
	// fetch the part of the PEM string between header and footer
	const cert = new x509.X509Certificate(pem)

	return await window.crypto.subtle.importKey(
		'spki',
		cert.publicKey.rawData,
		{
			name: 'RSA-OAEP',
			hash: 'SHA-256',
		},
		true,
		['encrypt']
	)
}

/**
 * @param {string} publicKey
 * @param {BufferSource} buffer
 * @return {Promise<ArrayBuffer>}
 */
async function encryptStringAsymmetric(publicKey, buffer) {
	return await window.crypto.subtle.encrypt(
		{ name: 'RSA-OAEP' },
		await importPublicKey(publicKey),
		buffer
	)
}

export {
	EncryptedFile,
	encryptStringAsymmetric,
}
