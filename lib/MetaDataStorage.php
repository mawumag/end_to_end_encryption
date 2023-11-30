<?php

declare(strict_types=1);
/**
 * @copyright Copyright (c) 2017 Bjoern Schiessle <bjoern@schiessle.org>
 * @copyright Copyright (c) 2020 Georg Ehrke <georg-nextcloud@ehrke.email>
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

namespace OCA\EndToEndEncryption;

use OC\User\NoUserException;
use OCA\EndToEndEncryption\Exceptions\MetaDataExistsException;
use OCA\EndToEndEncryption\Exceptions\MissingMetaDataException;
use OCP\Files\IAppData;
use OCP\Files\IRootFolder;
use OCP\Files\NotFoundException;
use OCP\Files\NotPermittedException;
use OCP\Files\SimpleFS\ISimpleFile;
use OCP\Files\SimpleFS\ISimpleFolder;

/**
 * Class MetaDataStorage
 *
 * @package OCA\EndToEndEncryption
 */
class MetaDataStorage implements IMetaDataStorage {
	private IAppData $appData;
	private IRootFolder $rootFolder;
	private string $metaDataRoot = '/meta-data';
	private string $metaDataFileName = 'meta.data';
	private string $intermediateMetaDataFileName = 'intermediate.meta.data';

	public function __construct(IAppData $appData,
								IRootFolder $rootFolder) {
		$this->appData = $appData;
		$this->rootFolder = $rootFolder;
	}

	/**
	 * @inheritDoc
	 */
	public function getMetaData(string $userId, int $id): string {
		$this->verifyFolderStructure();
		$this->verifyOwner($userId, $id);

		$legacyFile = $this->getLegacyFile($userId, $id);
		if ($legacyFile !== null) {
			return $legacyFile->getContent();
		}

		$folderName = $this->getFolderNameForFileId($id);
		$folder = $this->appData->getFolder($folderName);

		return $folder
			->getFile($this->metaDataFileName)
			->getContent();
	}

	/**
	 * @inheritDoc
	 */
	public function setMetaDataIntoIntermediateFile(string $userId, int $id, string $metaData, string $token): void {
		$this->verifyFolderStructure();
		$this->verifyOwner($userId, $id);

		$legacyFile = $this->getLegacyFile($userId, $id);
		if ($legacyFile !== null) {
			throw new MetaDataExistsException('Legacy Meta-data file already exists');
		}

		$folderName = $this->getFolderNameForFileId($id);
		try {
			$dir = $this->appData->getFolder($folderName);
		} catch (NotFoundException $ex) {
			$dir = $this->appData->newFolder($folderName);
		}

		// Do not override metadata-file
		if ($dir->fileExists($this->metaDataFileName)) {
			throw new MetaDataExistsException('Meta-data file already exists');
		}

		if ($dir->fileExists($this->intermediateMetaDataFileName)) {
			throw new MetaDataExistsException('Intermediate meta-data file already exists');
		}

		$dir->newFile($this->intermediateMetaDataFileName)
			->putContent($metaData);

		$this->getTokenFolder($token)->newFile("$id", '');
	}

	/**
	 * @inheritDoc
	 */
	public function updateMetaDataIntoIntermediateFile(string $userId, int $id, string $fileKey, string $token): void {
		// ToDo check signature for race condition
		$this->verifyFolderStructure();
		$this->verifyOwner($userId, $id);

		$legacyFile = $this->getLegacyFile($userId, $id);
		$folderName = $this->getFolderNameForFileId($id);
		try {
			$dir = $this->appData->getFolder($folderName);
		} catch (NotFoundException $ex) {
			// No folder and no legacy
			if ($legacyFile === null) {
				throw new MissingMetaDataException('Meta-data file missing');
			}

			$dir = $this->appData->newFolder($folderName);
		}

		if ($legacyFile === null && !$dir->fileExists($this->metaDataFileName)) {
			throw new MissingMetaDataException('Meta-data file missing');
		}

		try {
			$intermediateMetaDataFile = $dir->getFile($this->intermediateMetaDataFileName);
		} catch (NotFoundException $ex) {
			$intermediateMetaDataFile = $dir->newFile($this->intermediateMetaDataFileName);
		}

		$intermediateMetaDataFile
			->putContent($fileKey);

		$this->getTokenFolder($token)->newFile("$id", '');
	}

	/**
	 * @inheritDoc
	 */
	public function deleteMetaData(string $userId, int $id): void {
		$this->verifyFolderStructure();
		$this->verifyOwner($userId, $id);

		$folderName = $this->getFolderNameForFileId($id);
		try {
			$dir = $this->appData->getFolder($folderName);
		} catch (NotFoundException $ex) {
			return;
		}

		$dir->delete();
		$this->cleanupLegacyFile($userId, $id);
	}

	/**
	 * @inheritDoc
	 */
	public function saveIntermediateFile(string $userId, int $id): void {
		$this->verifyFolderStructure();
		$this->verifyOwner($userId, $id);

		$folderName = $this->getFolderNameForFileId($id);
		try {
			$dir = $this->appData->getFolder($folderName);
		} catch (NotFoundException $ex) {
			throw new MissingMetaDataException('Intermediate meta-data file missing');
		}

		if (!$dir->fileExists($this->intermediateMetaDataFileName)) {
			throw new MissingMetaDataException('Intermediate meta-data file missing');
		}

		$intermediateMetaDataFile = $dir->getFile($this->intermediateMetaDataFileName);
		// If the intermediate file is empty, delete the metadata file
		if ($intermediateMetaDataFile->getContent() === '{}') {
			$dir->delete();
		} else {
			try {
				$finalFile = $dir->getFile($this->metaDataFileName);
			} catch (NotFoundException $ex) {
				$finalFile = $dir->newFile($this->metaDataFileName);
			}

			$finalFile->putContent($intermediateMetaDataFile->getContent());
			// After successfully saving, automatically delete the intermediate file
			$intermediateMetaDataFile->delete();
		}

		$this->cleanupLegacyFile($userId, $id);
	}

	/**
	 * @inheritDoc
	 */
	public function deleteIntermediateFile(string $userId, int $id): void {
		$this->verifyFolderStructure();
		$this->verifyOwner($userId, $id);

		$folderName = $this->getFolderNameForFileId($id);
		try {
			$dir = $this->appData->getFolder($folderName);
		} catch (NotFoundException $ex) {
			return;
		}

		if (!$dir->fileExists($this->intermediateMetaDataFileName)) {
			return;
		}

		$dir->getFile($this->intermediateMetaDataFileName)
			->delete();
	}

	private function getFolderNameForFileId(int $id): string {
		return $this->metaDataRoot . '/' . $id;
	}

	/**
	 * Verifies that user has access to file-id
	 *
	 * @throws NotFoundException
	 */
	protected function verifyOwner(string $userId, int $id): void {
		try {
			$userFolder = $this->rootFolder->getUserFolder($userId);
		} catch (NoUserException | NotPermittedException $ex) {
			throw new NotFoundException('No user-root for '. $userId);
		}

		$ownerNodes = $userFolder->getById($id);
		if (!isset($ownerNodes[0])) {
			throw new NotFoundException('No file for owner with ID ' . $id);
		}
	}

	/**
	 * @throws NotFoundException
	 * @throws NotPermittedException
	 */
	protected function verifyFolderStructure(): void {
		$appDataRoot = $this->appData->getFolder('/');
		if (!$appDataRoot->fileExists($this->metaDataRoot)) {
			$this->appData->newFolder($this->metaDataRoot);
		}
	}

	/**
	 * @throws NotPermittedException
	 */
	protected function getLegacyFile(string $userId, int $id): ?ISimpleFile {
		try {
			$legacyOwnerPath = $this->getLegacyOwnerPath($userId, $id);
		} catch (NotFoundException $e) {
			// Just return if file does not exist for user
			return null;
		}

		try {
			$legacyFolder = $this->appData->getFolder($this->metaDataRoot . '/' . $legacyOwnerPath);
			return $legacyFolder->getFile($this->metaDataFileName);
		} catch (NotFoundException $e) {
			// Just return if no legacy file exits
			return null;
		}
	}

	/**
	 * @throws NotPermittedException
	 */
	protected function cleanupLegacyFile(string $userId, int $id): void {
		try {
			$legacyOwnerPath = $this->getLegacyOwnerPath($userId, $id);
		} catch (NotFoundException $e) {
			// Just return if file does not exist for user
			return;
		}

		try {
			$legacyFolder = $this->appData->getFolder($this->metaDataRoot . '/' . $legacyOwnerPath);
			$legacyFolder->delete();
		} catch (NotFoundException | NotPermittedException $e) {
			return;
		}
	}

	/**
	 * Get path to the file for the file-owner.
	 * This is needed for the old way of storing metadata-files.
	 *
	 * @throws NotFoundException
	 * @throws NotPermittedException
	 */
	protected function getLegacyOwnerPath(string $userId, int $id):string {
		try {
			$userFolder = $this->rootFolder->getUserFolder($userId);
		} catch (NoUserException $ex) {
			throw new NotFoundException('No user-root for '. $userId);
		}

		$ownerNodes = $userFolder->getById($id);
		if (!isset($ownerNodes[0])) {
			throw new NotFoundException('No file for owner with ID ' . $id);
		}

		return $ownerNodes[0]->getPath();
	}

	/**
	 * @inheritDoc
	 */
	public function getTouchedFolders(string $token): array {
		return array_map(
			fn (ISimpleFile $file) => (int)$file->getName(),
			$this->getTokenFolder($token)->getDirectoryListing()
		);
	}

	/**
	 * @inheritDoc
	 */
	public function clearTouchedFolders(string $token): void {
		$this->getTokenFolder($token)->delete();
	}

	// To ease the wrap-up process during unlocking,
	// we keep track of every folder for which metadata was updated.
	// For that we create a file named /tokens/$token/$folderId.
	private function getTokenFolder(string $token): ISimpleFolder {
		try {
			return $this->appData->getFolder("/tokens/$token");
		} catch (NotFoundException $ex) {
			return $this->appData->newFolder("/tokens/$token");
		}
	}
}
