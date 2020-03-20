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


use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use SimpleSAML\Modules\OAuth2\Entity\AuthCodeEntity;

class AuthCodeRepository extends AbstractRepository implements AuthCodeRepositoryInterface
{
    /**
     * @inheritDoc
     */
    public function getNewAuthCode()
    {
        return new AuthCodeEntity();
    }

    /**
     * @inheritDoc
     */
    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity)
    {
        $scopes = [];
        foreach ($authCodeEntity->getScopes() as $scope) {
            $scopes[] = $scope->getIdentifier();
        }

        $id = $authCodeEntity->getIdentifier();

        $this->store->set($this->getTableName(), $id, [
            'id' => $id,
            'scopes' => $scopes,
            'expires_at' => $authCodeEntity->getExpiryDateTime(),
            'user_id' => $authCodeEntity->getUserIdentifier(),
            'client_id' => $authCodeEntity->getClient()->getIdentifier(),
            'redirect_uri' => $authCodeEntity->getRedirectUri(),
            'is_revoked' => false
        ], $authCodeEntity->getExpiryDateTime()->getTimestamp());
    }

    /**
     * @inheritDoc
     */
    public function revokeAuthCode($codeId)
    {
        $c = $this->getValue($this->getTableName(), $codeId);

        if(is_null($c)){
            throw new SimpleSAML_Error_Exception("Access code not found", 8767);
        }

        $c['is_revoked'] = true;
        $this->store->set($this->getTableName(), $codeId, $c);
    }

    /**
     * @inheritDoc
     */
    public function isAuthCodeRevoked($codeId)
    {
        $c = $this->getValue($this->getTableName(), $codeId);

        if(is_null($c)){
            throw new SimpleSAML_Error_Exception("Access code not found", 8767);
        }

        return $c['is_revoked'];
    }

    public function removeExpiredAuthCodes()
    {
        $this->removeExpired($this->getTableName());
    }

    public function getTableName()
    {
        return 'oauth2_authcode';
    }
}