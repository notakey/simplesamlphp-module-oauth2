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


use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use SimpleSAML\Module\oauth2\Entity\ClientEntity;
use SimpleSAML\Utils\Random;

class ClientRepository extends AbstractRepository implements ClientRepositoryInterface
{
    /**
     * @inheritDoc
     */
    public function getClientEntity($clientIdentifier)
    {
        /** @var \SimpleSAML\Module\oauth2\Entity\ClientEntity $entity */
        $entity = $this->find($clientIdentifier);

        if (!$entity) {
            throw new \Exception("OAuth client entity not found");
        }

        $client = new ClientEntity();
        $client->setIdentifier($clientIdentifier);
        $client->setName($entity['name']);
        $client->setRedirectUri($entity['redirect_uri']);
        $client->setSecret($entity['secret']);

        return $client;
    }

    public function persistNewClient($id, $secret, $name, $description, $redirectUri)
    {
        if (false === is_array($redirectUri)) {
            if (is_string($redirectUri)) {
                $redirectUri = [$redirectUri];
            } else {
                throw new \InvalidArgumentException('Client redirect URI must be a string or an array.');
            }
        }

        $this->store->set($this->getTableName(), $id, [
            'id' => $id,
            'secret' => $secret,
            'name' => $name,
            'description' => $description,
            'redirect_uri' => $redirectUri,
            'scopes' => ['basic'],
        ]);
    }

    public function updateClient($id, $name, $description, $redirectUri)
    {
        $v = $this->find($id);

        if (!$v) {
            throw new  \SimpleSAML\Error\Exception("OAuth client not found", 8769);
        }

        $this->store->set($this->getTableName(), $id, [
            'id' => $id,
            'name' => $name,
            'secret' => $v['secret'],
            'description' => $description,
            'redirect_uri' => $redirectUri,
            'scopes' => ['basic'],
        ]);
    }

    public function delete($clientIdentifier)
    {
        $this->store->delete($this->getTableName(), $clientIdentifier);
    }

    public function find($clientIdentifier)
    {
        if (is_null($clientIdentifier)) {
            throw new  \SimpleSAML\Error\Exception("OAuth clientIdentifier cannot be empty", 8767);
        }

        $client = $this->store->get($this->getTableName(), $clientIdentifier);

        // if ($client) {
        //     $client['redirect_uri'] = $this->store->convertToPHPValue($client['redirect_uri'], 'json_array' );
        //     $client['scopes'] = $this->store->convertToPHPValue($client['scopes'], 'json_array' );
        // }

        return $client;
    }

    public function findAll()
    {
        $clients = $this->store->get($this->getTableName(), null);

        // foreach ($clients as &$client) {
        //     $client['redirect_uri'] = $this->store->convertToPHPValue($client['redirect_uri'], 'json_array' );
        //     $client['scopes'] = $this->store->convertToPHPValue($client['scopes'], 'json_array' );
        // }

        return $clients;
    }

    public function getTableName()
    {
        return 'oauth2_client';
    }

    public function restoreSecret($clientIdentifier)
    {
        $secret = Random::generateID();
        $v = $this->find($clientIdentifier);
        $v['secret'] = $secret;
        $this->store->set($this->getTableName(), $clientIdentifier, $v);
    }

    public function validateClient($clientIdentifier, $clientSecret, $grantType)
    {
        $entity = $this->find($clientIdentifier);

        if (!$entity) {
            return false;
        }

        if ($clientSecret && $clientSecret !== $entity['secret']) {
            return false;
        }

        return true;
    }
}
