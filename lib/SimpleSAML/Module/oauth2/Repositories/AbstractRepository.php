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


abstract class AbstractRepository
{
    /**
     * @var DBAL
     */
    protected $store;

    /**
     * @var \SimpleSAML\Configuration
     */
    protected $config;

    /**
     * ClientRepository constructor.
     */
    public function __construct()
    {
        $this->config = \SimpleSAML\Configuration::getOptionalConfig('module_oauth2.php');
        $this->store = \SimpleSAML\Store::getInstance();
    }

    public function getValue($table_name, $id)
    {
        return $this->store->get($table_name, $id);
    }

    public function removeExpired($table_name)
    {
        $tarr = $this->store->get($table_name, null);

        foreach ($tarr as $t) {
            if ($t['expires_at']->getTimestamp() < time()) {
                $this->store->delete($table_name, $t['id']);
            }
        }
    }

    abstract public function getTableName();
}
