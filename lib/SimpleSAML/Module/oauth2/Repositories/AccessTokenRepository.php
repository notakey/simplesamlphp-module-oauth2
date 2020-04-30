<?php
/*
 * This file is part of the simplesamlphp-module-oauth2.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oauth2\Repositories;


use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oauth2\Entity\AccessTokenEntity;

class AccessTokenRepository extends AbstractRepository implements AccessTokenRepositoryInterface
{
    /**
     * @inheritDoc
     */
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null)
    {
        $accessToken = new AccessTokenEntity();
        $accessToken->setClient($clientEntity);
        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        return $accessToken;
    }

    /**
     * @inheritDoc
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity)
    {
        $scopes = [];
        foreach ($accessTokenEntity->getScopes() as $scope) {
            $scopes[] = $scope->getIdentifier();
        }

        $id = $accessTokenEntity->getIdentifier();

        $this->store->set(
            $this->getTableName(),
            $id,
            [
                'id' => $id,
                'scopes' => $scopes,
                'expires_at' => $accessTokenEntity->getExpiryDateTime(),
                'user_id' => $accessTokenEntity->getUserIdentifier(),
                'client_id' => $accessTokenEntity->getClient()->getIdentifier(),
                'is_revoked' => false
            ],
            $accessTokenEntity->getExpiryDateTime()->getTimestamp()
        );
    }

    public function getUserId($tokenId)
    {
        $t = $this->getValue($this->getTableName(), $tokenId);

        if (is_null($t)) {
            throw new  \SimpleSAML\Error\Exception("Token not found", 8767);
        }

        return $t['user_id'];
    }

    /**
     * @inheritDoc
     */
    public function revokeAccessToken($tokenId)
    {
        $t = $this->getValue($this->getTableName(), $tokenId);

        if (is_null($t)) {
            throw new  \SimpleSAML\Error\Exception("Token not found", 8767);
        }

        $t['is_revoked'] = true;

        $this->store->set($this->getTableName(), $tokenId, $t);
    }

    /**
     * @inheritDoc
     */
    public function isAccessTokenRevoked($tokenId)
    {
        $t = $this->getValue($this->getTableName(), $tokenId);

        if (is_null($t)) {
            throw new  \SimpleSAML\Error\Exception("Token not found", 8767);
        }

        return $t['is_revoked'];
    }

    public function removeExpiredAccessTokens()
    {
        $this->removeExpired($this->getTableName());
    }

    public function getTableName()
    {
        return 'oauth2_accesstoken';
    }
}
