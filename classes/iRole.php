<?php
namespace Acl;

/**
 * Role interface.
 * Can be implemented in real model for more convenient access to ACL features.
 *
 * @package Erum
 * @subpackage Acl
 * @author Andrew Tereshko <andrew.tereshko@gmail.com>
 */
interface iRole
{
    /**
     * Returns current Role id.
     *
     * @return string
     */
    public function getRoleId();

    /**
     * Checks whether it is possible to use $recource and $action (optional) for the current Role.
     *
     * @param string | \Acl\iResource $resource
     * @param string $action
     * @return boolean
     */
    public function isAllowed( $resource, $action = null );
}
