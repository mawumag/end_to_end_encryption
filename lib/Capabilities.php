<?php

declare(strict_types=1);
/**
 * @copyright Copyright (c) 2017 Bjoern Schiessle <bjoern@schiessle.org>
 * @copyright Copyright (c) 2022 Carl Schwan <carl@carlschwan.eu>
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

use OCP\IUserSession;
use OCP\IUser;
use OCP\Capabilities\ICapability;

class Capabilities implements ICapability {
	private Config $config;
	private IUserSession $userSession;

	public function __construct(Config $config, IUserSession $userSession) {
		$this->config = $config;
		$this->userSession = $userSession;
	}

	public function getCapabilities(): array {
		$user = $this->userSession->getUser();
		if (!($user instanceof IUser) || $this->config->isDisabledForUser($user)) {
			return [];
		}

		$capabilities = ['end-to-end-encryption' =>
			[
				'enabled' => true,
				'api-version' => '1.1',
			]
		];

		return $capabilities;
	}
}
