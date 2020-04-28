<?php

declare(strict_types=1);
/**
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * @copyright Copyright (c) 2017 Bjoern Schiessle <bjoern@schiessle.org>
 *
 * @author Bjoern Schiessle <bjoern@schiessle.org>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\EndToEndEncryption\Controller;

use BadMethodCallException;
use Exception;
use OCA\EndToEndEncryption\EncryptionManager;
use OCA\EndToEndEncryption\Exceptions\FileLockedException;
use OCA\EndToEndEncryption\Exceptions\FileNotLockedException;
use OCA\EndToEndEncryption\Exceptions\KeyExistsException;
use OCA\EndToEndEncryption\Exceptions\MetaDataExistsException;
use OCA\EndToEndEncryption\Exceptions\MissingMetaDataException;
use OCA\EndToEndEncryption\IKeyStorage;
use OCA\EndToEndEncryption\IMetaDataStorage;
use OCA\EndToEndEncryption\LockManager;
use OCA\EndToEndEncryption\SignatureHandler;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSBadRequestException;
use OCP\AppFramework\OCS\OCSForbiddenException;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\AppFramework\OCSController;
use OCP\Files\ForbiddenException;
use OCP\Files\NotFoundException;
use OCP\Files\NotPermittedException;
use OCP\IL10N;
use OCP\ILogger;
use OCP\IRequest;
use function in_array;
use function json_decode;

/**
 * Class RequestHandlerController
 *
 * handle API calls from the client to the server
 *
 * @package OCA\EndToEndEncryption\Controller
 */
class RequestHandlerController extends OCSController {

	/** @var  string */
	private $userId;

	/** @var IKeyStorage */
	private $keyStorage;

	/** @var IMetaDataStorage */
	private $metaDataStorage;

	/** @var SignatureHandler */
	private $signatureHandler;

	/** @var EncryptionManager */
	private $manager;

	/** @var ILogger */
	private $logger;

	/** @var LockManager */
	private $lockManager;

	/** @var IL10N */
	private $l;

	/**
	 * RequestHandlerController constructor.
	 *
	 * @param string $AppName
	 * @param IRequest $request
	 * @param string $UserId
	 * @param IKeyStorage $keyStorage
	 * @param IMetaDataStorage $metaDataStorage
	 * @param SignatureHandler $signatureHandler
	 * @param EncryptionManager $manager
	 * @param LockManager $lockManager
	 * @param ILogger $logger
	 * @param IL10N $l
	 */
	public function __construct($AppName,
								IRequest $request,
								$UserId,
								IKeyStorage $keyStorage,
								IMetaDataStorage $metaDataStorage,
								SignatureHandler $signatureHandler,
								EncryptionManager $manager,
								LockManager $lockManager,
								ILogger $logger,
								IL10N $l
	) {
		parent::__construct($AppName, $request);
		$this->userId = $UserId;
		$this->keyStorage = $keyStorage;
		$this->metaDataStorage = $metaDataStorage;
		$this->signatureHandler = $signatureHandler;
		$this->manager = $manager;
		$this->logger = $logger;
		$this->lockManager = $lockManager;
		$this->l = $l;
	}

	/**
	 * get private key
	 *
	 * @NoAdminRequired
	 *
	 * @return DataResponse
	 *
	 * @throws OCSBadRequestException
	 * @throws OCSForbiddenException
	 * @throws OCSNotFoundException
	 */
	public function getPrivateKey(): DataResponse {
		try {
			$privateKey = $this->keyStorage->getPrivateKey($this->userId);
			return new DataResponse(['private-key' => $privateKey]);
		} catch (ForbiddenException $e) {
			throw new OCSForbiddenException($this->l->t('This is someone else\'s private key'));
		} catch (NotFoundException $e) {
			throw new OCSNotFoundException($this->l->t('Could not find the private key of the user %s', [$this->userId]));
		} catch (Exception $e) {
			$error = 'Can\'t get private key: ' . $e->getMessage();
			$this->logger->error($error, ['app' => 'end_to_end_encryption']);
			throw new OCSBadRequestException($this->l->t('Internal error'));
		}
	}

	/**
	 * delete the users private key
	 *
	 * @NoAdminRequired
	 *
	 * @return DataResponse
	 *
	 * @throws OCSBadRequestException
	 * @throws OCSForbiddenException
	 * @throws OCSNotFoundException
	 */
	public function deletePrivateKey(): DataResponse {
		try {
			$this->keyStorage->deletePrivateKey($this->userId);
			return new DataResponse();
		} catch (NotPermittedException $e) {
			throw new OCSForbiddenException($this->l->t('You are not allowed to delete this private key'));
		} catch (NotFoundException $e) {
			throw new OCSNotFoundException($this->l->t('Could not find the private key belonging to the user %s', [$this->userId]));
		} catch (Exception $e) {
			$error = 'Can\'t find private key: ' . $e->getMessage();
			$this->logger->error($error, ['app' => 'end_to_end_encryption']);
			throw new OCSBadRequestException($this->l->t('Internal error'));
		}
	}


	/**
	 * set private key
	 *
	 * @NoAdminRequired
	 *
	 * @param string $privateKey
	 * @return DataResponse
	 *
	 * @throws OCSBadRequestException
	 */
	public function setPrivateKey(string $privateKey): DataResponse {
		try {
			$this->keyStorage->setPrivateKey($privateKey, $this->userId);
		} catch (KeyExistsException $e) {
			return new DataResponse([], Http::STATUS_CONFLICT);
		} catch (Exception $e) {
			$error = 'Can\'t store private key: ' . $e->getMessage();
			$this->logger->error($error, ['app' => 'end_to_end_encryption']);
			throw new OCSBadRequestException($this->l->t('internal error'));
		}

		return new DataResponse(['private-key' => $privateKey]);
	}

	/**
	 * get public key
	 *
	 * @NoAdminRequired
	 *
	 * @param string $users a json encoded list of users
	 * @return DataResponse
	 *
	 * @throws OCSBadRequestException
	 * @throws OCSNotFoundException
	 */
	public function getPublicKeys(string $users = ''): DataResponse {
		$usersArray = $this->jsonDecode($users);

		$result = ['public-keys' => []];
		foreach ($usersArray as $uid) {
			try {
				$publicKey = $this->keyStorage->getPublicKey($uid);
				$result['public-keys'][$uid] = $publicKey;
			} catch (NotFoundException $e) {
				throw new OCSNotFoundException($this->l->t('Could not find the public key belonging to the user %s', [$uid]));
			} catch (Exception $e) {
				$error = 'Can\'t get public keys: ' . $e->getMessage();
				$this->logger->error($error, ['app' => 'end_to_end_encryption']);
				throw new OCSBadRequestException($this->l->t('Internal error'));
			}
		}

		return new DataResponse($result);
	}

	/**
	 * create public key, store it on the server and return it to the user
	 *
	 * if no public key exists and the request contains a valid certificate
	 * from the currently logged in user we will create one
	 *
	 * @NoAdminRequired
	 *
	 * @param string $csr request to create a valid public key
	 * @return DataResponse
	 *
	 * @throws OCSForbiddenException
	 * @throws OCSBadRequestException
	 */
	public function createPublicKey(string $csr): DataResponse {
		if ($this->keyStorage->publicKeyExists($this->userId)) {
			return new DataResponse([], Http::STATUS_CONFLICT);
		}

		try {
			$subject = openssl_csr_get_subject($csr);
			$publicKey = $this->signatureHandler->sign($csr);
		} catch (BadMethodCallException $e) {
			$error = 'Can\'t create public key: ' . $e->getMessage();
			$this->logger->error($error, ['app' => 'end_to_end_encryption']);
			throw new OCSBadRequestException($this->l->t($e->getMessage()));
		} catch (Exception $e) {
			$error = 'Can\'t create public key: ' . $e->getMessage();
			$this->logger->error($error, ['app' => 'end_to_end_encryption']);
			throw new OCSBadRequestException($this->l->t('Internal error'));
		}

		$cn = isset($subject['CN']) ? $subject['CN'] : '';
		if ($cn !== $this->userId) {
			throw new OCSForbiddenException($this->l->t('Common name (CN) does not match the current user'));
		}

		$this->keyStorage->setPublicKey($publicKey, $this->userId);

		return new DataResponse(['public-key' => $publicKey]);
	}

	/**
	 * delete the users public key
	 *
	 * @NoAdminRequired
	 *
	 * @return DataResponse
	 *
	 * @throws OCSForbiddenException
	 * @throws OCSBadRequestException
	 * @throws OCSNotFoundException
	 */
	public function deletePublicKey(): ?DataResponse {
		try {
			$this->keyStorage->deletePublicKey($this->userId);
			return new DataResponse();
		} catch (NotFoundException $e) {
			throw new OCSNotFoundException($this->l->t('Could not find the public key belonging to %s', [$this->userId]));
		} catch (NotPermittedException $e) {
			throw new OCSForbiddenException($this->l->t('This is not your private key to delete'));
		} catch (Exception $e) {
			$error = 'Can\'t delete public keys: ' . $e->getMessage();
			$this->logger->error($error, ['app' => 'end_to_end_encryption']);
			throw new OCSBadRequestException($this->l->t('Internal error'));
		}
	}


	/**
	 * get metadata
	 *
	 * @NoAdminRequired
	 *
	 * @param int $id file id
	 * @return DataResponse
	 *
	 * @throws OCSNotFoundException
	 * @throws OCSBadRequestException
	 */
	public function getMetaData(int $id): DataResponse {
		try {
			$metaData = $this->metaDataStorage->getMetaData($id);
		} catch (NotFoundException $e) {
			throw new OCSNotFoundException($this->l->t('Could not find metadata for "%s"', [$id]));
		} catch (Exception $e) {
			$error = 'Can\'t read metadata: ' . $e->getMessage();
			$this->logger->error($error, ['app' => 'end_to_end_encryption']);
			throw new OCSBadRequestException($this->l->t("Can\'t read metadata"));
		}
		return new DataResponse(['meta-data' => $metaData]);
	}

	/**
	 * set metadata
	 *
	 * @NoAdminRequired
	 *
	 * @param int $id file id
	 * @param string $metaData
	 * @return DataResponse
	 *
	 * @throws OCSNotFoundException
	 * @throws OCSBadRequestException
	 */
	public function setMetaData(int $id, string $metaData): DataResponse {
		try {
			$this->metaDataStorage->setMetaDataIntoIntermediateFile($id, $metaData);
		} catch (MetaDataExistsException $e) {
			return new DataResponse([], Http::STATUS_CONFLICT);
		} catch (NotFoundException $e) {
			throw new OCSNotFoundException($this->l->t($e->getMessage()));
		} catch (Exception $e) {
			$error = 'Can\'t store metadata: ' . $e->getMessage();
			$this->logger->error($error, ['app' => 'end_to_end_encryption']);
			throw new OCSBadRequestException($this->l->t("Can\'t store metadata"));
		}

		return new DataResponse(['meta-data' => $metaData]);
	}

	/**
	 * update metadata
	 *
	 * @NoAdminRequired
	 *
	 * @param int $id file id
	 * @param string $metaData
	 *
	 * @return DataResponse
	 * @throws OCSForbiddenException
	 * @throws OCSBadRequestException
	 * @throws OCSNotFoundException
	 */
	public function updateMetaData(int $id, string $metaData): DataResponse {
		$e2eToken = $this->request->getParam('e2e-token');

		if ($this->lockManager->isLocked($id, $e2eToken)) {
			throw new OCSForbiddenException($this->l->t('You are not allowed to edit the file, make sure to first lock it, and then send the right token'));
		}

		try {
			$this->metaDataStorage->updateMetaDataIntoIntermediateFile($id, $metaData);
		} catch (MissingMetaDataException $e) {
			throw new OCSNotFoundException($this->l->t("Metadata-file doesn\'t exist"));
		} catch (NotFoundException $e) {
			throw new OCSNotFoundException($this->l->t($e->getMessage()));
		} catch (Exception $e) {
			$error = 'Can\'t store metadata: ' . $e->getMessage();
			$this->logger->error($error, ['app' => 'end_to_end_encryption']);
			throw new OCSBadRequestException($this->l->t("Can\'t store metadata"));
		}

		return new DataResponse(['meta-data' => $metaData]);
	}

	/**
	 * delete metadata
	 *
	 * @NoAdminRequired
	 *
	 * @param int $id file id
	 * @return DataResponse
	 *
	 * @throws OCSForbiddenException
	 * @throws OCSNotFoundException
	 * @throws OCSBadRequestException
	 */
	public function deleteMetaData(int $id): DataResponse {
		try {
			$this->metaDataStorage->deleteMetaData($id);
		} catch (NotFoundException $e) {
			throw new OCSNotFoundException($this->l->t('Could not find metadata for "%s"', [$id]));
		} catch (NotPermittedException $e) {
			throw new OCSForbiddenException($this->l->t('Only the owner can delete the metadata-file'));
		} catch (Exception $e) {
			$error = 'Internal server error: ' . $e->getMessage();
			$this->logger->error($error, ['app' => 'end_to_end_encryption']);
			throw new OCSBadRequestException($this->l->t("Can\'t delete metadata"));
		}
		return new DataResponse();
	}


	/**
	 * @NoAdminRequired
	 *
	 * get the public server key so that the clients can verify the
	 * signature of the users public keys
	 *
	 * @return DataResponse
	 *
	 * @throws OCSBadRequestException
	 */
	public function getPublicServerKey(): DataResponse {
		try {
			$publicKey = $this->signatureHandler->getPublicServerKey();
		} catch (Exception $e) {
			$error = 'Can\'t read server wide public key: ' . $e->getMessage();
			$this->logger->error($error, ['app' => 'end_to_end_encryption']);
			throw new OCSBadRequestException($this->l->t('Internal error'));
		}

		return new DataResponse(['public-key' => $publicKey]);
	}

	/**
	 * @NoAdminRequired
	 *
	 * set encryption flag for folder
	 *
	 * @param int $id file ID
	 * @return DataResponse
	 *
	 * @throws OCSNotFoundException
	 */
	public function setEncryptionFlag(int $id): DataResponse {
		try {
			$this->manager->setEncryptionFlag($id);
		} catch (NotFoundException $e) {
			throw new OCSNotFoundException($this->l->t($e->getMessage()));
		}

		return new DataResponse();
	}

	/**
	 * @NoAdminRequired
	 *
	 * set encryption flag for folder
	 *
	 * @param int $id file ID
	 * @return DataResponse
	 *
	 * @throws OCSNotFoundException
	 */
	public function removeEncryptionFlag(int $id): DataResponse {
		try {
			$this->manager->removeEncryptionFlag($id);
		} catch (NotFoundException $e) {
			throw new OCSNotFoundException($this->l->t($e->getMessage()));
		}

		try {
			$this->keyStorage->deleteMetaData($id);
		} catch (Exception $e) {
			$error = 'Internal server error: ' . $e->getMessage();
			$this->logger->error($error, ['app' => 'end_to_end_encryption']);
		}

		return new DataResponse();
	}

	/**
	 * lock folder
	 *
	 * @NoAdminRequired
	 *
	 * @param int $id file ID
	 *
	 * @return DataResponse
	 * @throws OCSForbiddenException
	 */
	public function lockFolder(int $id): DataResponse {
		$e2eToken = $this->request->getParam('e2e-token', '');

		$newToken = $this->lockManager->lockFile($id, $e2eToken);
		if ($newToken === null) {
			throw new OCSForbiddenException($this->l->t('File already locked'));
		}
		return new DataResponse(['e2e-token' => $newToken]);
	}


	/**
	 * unlock folder
	 *
	 * @NoAdminRequired
	 *
	 * @param int $id file ID
	 *
	 * @return DataResponse
	 * @throws OCSNotFoundException
	 * @throws OCSForbiddenException
	 */
	public function unlockFolder(int $id): DataResponse {
		$token = $this->request->getHeader('e2e-token');

		try {
			$this->lockManager->unlockFile($id, $token);
		} catch (FileLockedException $e) {
			throw new OCSForbiddenException($this->l->t('You are not allowed to remove the lock'));
		} catch (FileNotLockedException $e) {
			throw new OCSNotFoundException($this->l->t('File not locked'));
		}

		$this->metaDataStorage->saveIntermediateFile($id);

		return new DataResponse();
	}

	/**
	 * decode JSON-encoded userlist and return an array
	 * add the currently logged in user if the user isn't part of the list
	 *
	 * @param string $users JSON-encoded userlist
	 * @return array
	 * @throws OCSBadRequestException
	 */
	private function jsonDecode(string $users): array {
		$usersArray = [];
		if (!empty($users)) {
			// TODO - use JSON_THROW_ON_ERROR once we require PHP 7.3
			$usersArray = json_decode($users, true);
			if ($usersArray === null) {
				throw new OCSBadRequestException($this->l->t('Can not decode userlist'));
			}
		}

		if (!in_array($this->userId, $usersArray, true)) {
			$usersArray[] = $this->userId;
		}

		return $usersArray;
	}
}
