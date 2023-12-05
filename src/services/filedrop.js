import axios from '@nextcloud/axios'
import { generateOcsUrl } from '@nextcloud/router'
import { EncryptedFile } from './crypto.js'

/**
 * @typedef {object} FileMetadata
 * @property {string} filename - Original file name (ex: "/foo/test.txt")
 * @property {string} mimetype - Mimetype, if unknown use "application/octet-stream" (ex: "plain/text")
 * @property {string} key - Encryption key of the file (ex: "jtboLmgGR1OQf2uneqCVHpklQLlIwWL5TXAQ0keK")
 * @property {string} nonce - TODO: what is it?
 * @property {string} authenticationTag - Authentication tag of the file (ex: "LYRaJghbZUzBiNWb51ypWw==")
 */

/**
 * @typedef {object} UserEncryptionInformation
 * @property {string } userId
 * @property {string } encryptedFiledropKey
 */

/**
 * @typedef {object} FileDropPayload
 * @property {string } ciphertext
 * @property {string } nonce
 * @property {string } authenticationTag
 * @property {UserEncryptionInformation[]} users
 */

/**
 * @param {ArrayBuffer} buffer
 * @return {string}
 */
export function bufferToBase64(buffer) {
	return btoa(String.fromCharCode(...new Uint8Array(buffer)))
}

/**
 * @param {EncryptedFile} file
 * @param {Uint8Array} tag
 * @return {Promise<Object<string, FileMetadata>>}
 */
export async function getFileDropEntry(file, tag) {
	const rawFileEncryptionKey = await window.crypto.subtle.exportKey('raw', await file.getEncryptionKey())

	return {
		[file.encryptedFileName]: {
			filename: file.originalFileName,
			mimetype: file.mimetype,
			nonce: bufferToBase64(file.initializationVector),
			key: bufferToBase64(rawFileEncryptionKey),
			authenticationTag: bufferToBase64(tag),
		},
	}
}

/**
 * @param {1|2} encryptionVersion - The encrypted version for the folder
 * @param {number} folderId
 * @param {FileDropPayload} payload
 * @param {string} lockToken
 * @param {string} shareToken
 */
export async function uploadFileDrop(encryptionVersion, folderId, payload, lockToken, shareToken) {
	const ocsUrl = generateOcsUrl(
		'apps/end_to_end_encryption/api/v{encryptionVersion}/meta-data/{folderId}',
		{
			encryptionVersion,
			folderId,
		}
	)

	const { data: { ocs: { meta } } } = await axios.put(
		`${ocsUrl}/filedrop`,
		{
			fileDrop: JSON.stringify(payload),
		},
		{
			headers: {
				'x-e2ee-supported': true,
				...(encryptionVersion === 2 ? { 'e2e-token': lockToken } : {}),
			},
			params: {
				shareToken,
				...(encryptionVersion === 1 ? { 'e2e-token': lockToken } : {}),
			},
		},
	)

	if (meta.statuscode !== 200) {
		throw new Error(`Failed to upload metadata: ${meta.message}`)
	}
}
