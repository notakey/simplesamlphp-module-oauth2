<?php
/*
 * This file is part of the jt2016-uco-spa.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */


namespace SimpleSAML\Modules\OAuth2\Repositories;


use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;

class UserRepository extends AbstractRepository implements UserRepositoryInterface
{
    public function getUserEntityByUserCredentials(
        $username,
        $password,
        $grantType,
        ClientEntityInterface $clientEntity
    )
    {
        throw new \Exception('Not supported');
    }

    public function persistNewUser($id, $attributes)
    {
        $now = new \DateTime();

        $this->store->set($this->getTableName(), $id,
            [
                'id' => $id,
                'attributes' => $attributes,
                'created_at' => $now,
                'updated_at' => $now,
            ]
        );
    }

    public function updateUser($id, $attributes)
    {
        $now = new \DateTime();
        $user = $this->getValue($this->getTableName(), $id);
        $user['attributes'] = $attributes;
        $user['updated_at'] = $now;

        return $this->store->set($this->getTableName(), $id, $user);
    }

    public function delete($userIdentifier)
    {
        $this->store->delete($this->getTableName(), $userIdentifier);
    }

    public function insertOrCreate($userId, $attributes)
    {
        $user = $this->getValue($this->getTableName(), $userId);
        if (is_null($user)) {
            $this->persistNewUser($userId, $attributes);
        }else{
            $this->updateUser($userId, $attributes);
        }
    }

    public function getAttributes($userId)
    {
        $user = $this->getValue($this->getTableName(), $userId);

        return $user['attributes'];
    }

    public function getTableName()
    {
        return 'oauth2_user';
    }
}