// SPDX-FileCopyrightText: 2022 Carl Schwan <carl@carlschwan.eu>
// SPDX-License-Identifier: AGPL-3.0-or-later

import { generateOcsUrl } from '@nextcloud/router'
import axios from '@nextcloud/axios'

/**
 * @param {1|2} encryptionVersion - The encrypted version for the folder
 * @param {number} counter - The metadata counter received from the initial state
 * @param {number} fileId - The file id to lock
 * @param {?string} shareToken - The optional share token if this is a file drop.
 * @return {Promise<string>} lockToken
 */
export async function lock(encryptionVersion, counter, fileId, shareToken) {
	const { data: { ocs: { meta, data } } } = await axios.post(
		generateOcsUrl('apps/end_to_end_encryption/api/v{encryptionVersion}/lock/{fileId}', { encryptionVersion, fileId }),
		undefined,
		{
			headers: {
				'x-e2ee-supported': true,
				'x-nc-e2ee-counter': counter,
			},
			params: {
				shareToken,
			},
		}
	)

	if (meta.statuscode !== 200) {
		throw new Error(`Failed to lock folder: ${meta.message}`)
	}

	return data['e2e-token']
}

/**
 * @param {1|2} encryptionVersion - The encrypted version for the folder
 * @param {number} fileId - The file id to lock
 * @param {string} lockToken - The optional lock token if the folder was already locked.
 * @param {?string} shareToken - The optional share token if this is a file drop.
 */
export async function unlock(encryptionVersion, fileId, lockToken, shareToken) {
	const { data: { ocs: { meta } } } = await axios.delete(
		generateOcsUrl('apps/end_to_end_encryption/api/v{encryptionVersion}/lock/{fileId}', { encryptionVersion, fileId }),
		{
			headers: {
				'x-e2ee-supported': true,
				'e2e-token': lockToken,
			},
			params: {
				shareToken,
			},
		}
	)

	if (meta.statuscode !== 200) {
		throw new Error(`Failed to unlock folder: ${meta.message}`)
	}
}
