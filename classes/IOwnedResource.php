<?php
namespace Acl;

/**
 * Owned resource interface.
 * Can be implemented for more convenient access to ACL features.
 *
 * Main difference from IResource - implemented resource must have an owner
 *
 * @package Erum
 * @subpackage Acl
 * @author Andrew Tereshko <andrew.tereshko@gmail.com>
 */
interface IOwnedResource extends iResource
{
    /**
     * Returns current Resource id.
     *
     * @return string
     */
    public function getResourceId();

    /**
     * Checks whether it is possible for the $role to execute $action (if any) on specified $resource.
     *
     * @param $role
     * @param string $action
     * @internal param \Acl\iRole|string $resource
     * @return boolean
     */
    public function isAllowed( $role, $action = null );

    /**
     * Returns some owner identity
     *
     * @return mixed
     */
    public function getOwnerId();
}
