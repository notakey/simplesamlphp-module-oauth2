<?php
/*
 * This file is part of the simplesamlphp-module-oauth2.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OAuth2\Repositories;


use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use SimpleSAML\Modules\OAuth2\Entity\RefreshTokenEntity;

class RefreshTokenRepository extends AbstractRepository implements RefreshTokenRepositoryInterface
{
    /**
     * @inheritDoc
     */
    public function getNewRefreshToken()
    {
        return new RefreshTokenEntity();
    }

    /**
     * @inheritDoc
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity)
    {
        $id = $refreshTokenEntity->getIdentifier();

        $this->store->set($this->getTableName(), $id, [
            'id' => $id,
            'expires_at' => $refreshTokenEntity->getExpiryDateTime(),
            'accesstoken_id' => $refreshTokenEntity->getAccessToken()->getIdentifier(),
        ], $refreshTokenEntity->getExpiryDateTime()->getTimestamp());
    }

    /**
     * @inheritDoc
     */
    public function revokeRefreshToken($tokenId)
    {
        $c = $this->getValue($this->getTableName(), $tokenId);

        if(is_null($c)){
            throw new SimpleSAML_Error_Exception("Refresh token not found", 8767);
        }

        $c['is_revoked'] = true;
        $this->store->set($this->getTableName(), $tokenId, $c);
    }

    /**
     * @inheritDoc
     */
    public function isRefreshTokenRevoked($tokenId)
    {
        $t = $this->getValue($this->getTableName(), $tokenId);

        if(is_null($t)){
            throw new SimpleSAML_Error_Exception("Token not found", 8767);
        }

        return $t['is_revoked'];
    }

    public function removeExpiredRefreshTokens()
    {
        $this->removeExpired($this->getTableName());
    }

    public function getTableName()
    {
        return 'oauth2_refreshtoken';
    }
}