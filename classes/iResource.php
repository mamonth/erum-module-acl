<?php
namespace Acl;

/**
 * Resource interface.
 * Can be implemented in real model for more convenient access to ACL features.
 *
 * @package Erum
 * @subpackage Acl
 * @author Andrew Tereshko <andrew.tereshko@gmail.com>
 */
interface iResource
{
    /**
     * Returns current Resource id.
     *
     * @return string
     */
    public function getResourceId();

    /**
     * Checks whether it is possible for the $role to use current Recource and $action (optional).
     *
     * @param string | \Acl\iRole $resource
     * @param string $action
     * @return boolean
     */
    public function isAllowed( $role, $action = null );
}
