<?php

/**
 * Access control layer implementation.
 * Inspired and mostly taken from Zend_Acl && Kohana A2 & Acl
 *
 * @package Erum
 * @subpackage Acl
 * @copyright  Copyright (c) 2005-2008 Zend Technologies USA Inc. (http://www.zend.com)
 * @license    http://framework.zend.com/license/new-bsd     New BSD License
 * @author Andrew Tereshko <andrew.tereshko@gmail.com>
 *
 */
class Acl extends \Erum\ModuleAbstract
{

    /**
     * Registered roles
     *
     * @var array
     */
    protected $roles = array( );
    /**
     * Registered resources
     *
     * @var array
     */
    protected $resources = array( );
    /**
     * Registered access rules
     *
     * @var array
     */
    protected $rules = array( );

    /**
     * Just for ModuleAbstract implementation
     *
     * @param array $config
     */
    public function __construct( array $config )
    {
        
    }

    /**
     * Only for automatic tips in NetBeans.
     *
     * @param string $configAlias
     * @return \Acl
     */
    public static function factory( $configAlias = 'default' )
    {
        return parent::factory( $configAlias );
    }

    /**
     * Check is $resource and $action allowed for $role
     * 
     * @param array | string | \Acl\iRole $roles
     * @param string | \Acl\iResource $resource
     * @param string $action
     * @param function $callback
     * @return boolean
     */
    public function isAllowed( $roles, $resource, $action, $callback = null )
    {
        if( is_array( $roles ) )
        {
            $roles = array_map( function( $role )
                    {
                        return Acl::getRoleId( $role );
                    }, $roles );
        }
        elseif( $roles instanceof \Acl\iRole )
        {
            $roles = array( Acl::getRoleId( $roles ) );
        }
        else
        {
            $roles = (array)$roles;
        }
        
        $resource = $this->hasResource( $resource ) ? self::getResourceId( $resource ) : null;
        
        // loop for matching rule
        do
        {
            if ( ($rule = $this->findMatchRole( $resource, $roles, $action ) ) )
            {
                return $rule['allow'];
            }
        }
        // go level up in resources tree (child resources inherit rules from parent)
        while ( null !== $resource && ( $resource = $this->resources[$resource]['parent'] ) );

        return false;
    }

    /**
     * Add allow rule.
     * Any of params can be null (means all)
     * 
     * @param \Acl\iRole | string $role
     * @param \Acl\iResource | string $resource
     * @param string $action
     * @return Acl
     */
    public function allow( $role, $resource, $action )
    {
        $this->addRule( true, $role, $resource, $action );

        return $this;
    }

    /**
     * Add deny rule.
     * Any of params can be null (means all)
     * 
     * @param \Acl\iRole | string $role
     * @param \Acl\iResource | string $resource
     * @param string $action
     * @return Acl
     */
    public function deny( $role, $resource, $action )
    {
        $this->addRule( false, $role, $resource, $action );

        return $this;
    }

    /**
     * Add a new role.
     * 
     * @param string | \Acl\iRole $role
     * @param array | string | \Acl\iRole $parents
     * @return Acl
     */
    public function addRole( $role, $parents = null )
    {
        $parents = null === $parents ? null : (array) $parents;

        $role = $this->getRoleId( $role );

        if ( null !== $parents )
        {
            foreach ( $parents as $parentRole )
            {
                if ( !$this->hasRole( $parentRole ) )
                {
                    Throw new \Acl\Exception( 'The role "' . $parentRole . '" specified as a parent for the "' . $role . '" does not exist !' );
                }

                $this->roles[$parentRole]['children'][] = $role;
            }
        }

        $this->roles[$role] = array(
            'children' => array( ),
            'parents' => $parents
        );

        return $this;
    }

    /**
     * Checks whether there is a role.
     * 
     * @param type $role
     * @return type 
     */
    public function hasRole( $role )
    {
        return isset( $this->roles[$this->getRoleId( $role )] );
    }

    /**
     * Add new resource.
     * 
     * @param string | \Acl\iResource $role
     * @param string | \Acl\iResource $parents
     * @return Acl
     */
    public function addResource( $resource, $parent = null )
    {
        if ( null !== $parent )
        {
            if ( !$this->hasResource( $parent ) )
            {
                Throw new \Acl\Exception( 'The resource "' . $parent . '" specified as a parent for the "' . $resource . '" does not exist !' );
            }

                $this->resources[$parent]['children'][] = $resource;
        }

        $this->resources[$resource] = array(
            'children' => array( ),
            'parent' => $parent
        );

        return $this;
    }

    /**
     * Checks whether there is a resource.
     * 
     * @param \Acl\iResource | string $resource
     * @return boolean 
     */
    public function hasResource( $resource )
    {
        return isset( $this->resources[$this->getResourceId( $resource )] );
    }

    /**
     * Internal method for rules adding
     * 
     * @param bool $allow
     * @param array $roles
     * @param array $resources
     * @param array $actions
     */
    protected function addRule( $allow, $roles, $resources, $actions )
    {
        // normalize input values
        $allow = $allow ? true : false;

        $roles = null === $roles ? null : array_map( function( $role )
                        {
                            return Acl::getRoleId( $role );
                        }, (array) $roles );

        $resources = null === $resources ? null : array_map( function( $res )
                        {
                            return Acl::getResourceId( $res );
                        }, (array) $resources );

        $actions = null === $actions ? null : (array) $actions;


        //Building rule from bottom to top
        $rule = array(
            'allow' => $allow,
                //'assert' => $assertion,
        );

        $rule = null === $actions ? array( 'allActions' => $rule ) : array( 'byActionId' => array_fill_keys( $actions, $rule ) );
        $rule = null === $roles ? array( 'allRoles' => $rule ) : array( 'byRoleId' => array_fill_keys( $roles, $rule ) );
        $rule = null === $resources ? array( 'allResources' => $rule ) : array( 'byResourceId' => array_fill_keys( $resources, $rule ) );

        $this->rules = \Erum\Arr::merge( $this->rules, $rule );
    }

    /**
     * Try to find a matching rule based for supplied role and its parents (if any)
     *
     * @param string $resource  resource id
     * @param array  $roles     array of role ids
     * @param string $action  action
     * @return array|boolean a matching rule on success, false otherwise.
     */
    protected function findMatchRole( $resource, $roles, $action )
    {
        foreach ( $roles as $role )
        {
            // role unknown - skip
            if ( null !== $role && !$this->hasRole( $role ) )
                continue;

            // find match for this role
            if ( ( $rule = $this->findMatch( $this->rules, $resource, $role, $action ) ) )
            {
                return $rule;
            }

            // try parents of role (starting at last added parent role)
            if ( null !== $role && !empty( $this->roles[$role]['parents'] ) )
            {
                // let's see if any of the parent roles for this role return a valid rule
                if ( ($rule = $this->findMatchRole( $resource, array_reverse( $this->_roles[$role]['parents'] ), $action ) ) !== false )
                {
                    return $rule;
                }
            }
        }

        return false;
    }

    /**
     * Try to find a matching rule based on the specific arguments
     *
     * @param array  $attach    the (remaining) rules array
     * @param string $resource  resource id
     * @param string $role      role id
     * @param string $action action
     * @return array|boolean a matching rule on success, false otherwise.
     */
    private function findMatch( & $attach, $resource, $role, $action )
    {
        // resource level
        if ( false !== $resource )
        {
            if ( isset( $attach['byResourceId'][$resource] ) && ($rule = $this->findMatch( $attach['byResourceId'][$resource], false, $role, $action ) ) )
            {
                return $rule;
            }
            elseif ( isset( $attach['allResources'] ) )
            {
                $attach = & $attach['allResources'];
            }
            else
            {
                return false;
            }
        }

        // role level
        if ( false !== $role )
        {
            if ( isset( $attach['byRoleId'][$role] ) && ($rule = $this->findMatch( $attach['byRoleId'][$role], false, false, $action ) ) )
            {
                return $rule;
            }
            elseif ( isset( $attach['allRoles'] ) )
            {
                $attach = & $attach['allRoles'];
            }
            else
            {
                return false;
            }
        }

        if ( null === $action )
        {
            $specificDeny = false;

            if ( isset( $attach['byActionId'] ) )
            {
                foreach ( $attach['byActionId'] as $rule )
                {
                    if ( $this->ruleRunnable( $rule, false ) )
                    {
                        $specificDeny = $rule;
                        break;
                    }
                }
            }

            if ( !empty( $attach['allActions'] ) && $this->ruleRunnable( $attach['allActions'] ) )
            {
                if ( $attach['allActions']['allow'] && $specificDeny !== false )
                {
                    return $specificDeny;
                }
                else
                {
                    return $attach['allActions'];
                }
            }
            else
            {
                return $specificDeny;

                /* if($specificDeny !== false)
                  {
                  return $specificDeny;
                  }
                  else
                  {
                  return false;
                  } */
            }
        }
        else
        {
            if ( empty( $attach['byActionId'] ) || !isset( $attach['byActionId'][$action] ) )
            {
                if ( !empty( $attach['allActions'] ) && $this->ruleRunnable( $attach['allActions'] ) )
                {
                    return $attach['allActions'];
                }
                else
                {
                    return false;
                }
            }
            elseif ( isset( $attach['byActionId'][$action] ) && $this->ruleRunnable( $attach['byActionId'][$action] ) )
            {
                return $attach['byActionId'][$action];
            }
            else
            {
                return false;
            }
        }

        // never reached
        return false;
    }

    /**
     * Verifies if rule can be applied to specified arguments
     *
     * @param  array   $rule  the rule
     * @param  boolean $allow verify if rule is allowing/denying
     * @return boolean rule can be applied to arguments
     */
    private function ruleRunnable( $rule, $allow = null )
    {
        if ( null !== $allow )
        {
            if ( $rule['allow'] !== $allow )
                return false;
        }

        if ( isset( $rule['assert'] ) )
        {
            return $rule['assert']->assert( $this, $this->command['role'], $this->command['resource'], $this->command['privilege'] );
        }

        return true;
    }

    /**
     * Return correct role id.
     * 
     * @param \Acl\iRole | string $role
     * @return string 
     */
    public function getRoleId( $role )
    {
        if ( ( is_object( $role ) && !$role instanceof \Acl\iRole ) || is_array( $role ) )
        {
            throw new \Acl\Exception( 'Role must be string (integer) or iRole implemented object, ' . gettype( $role ) . ' given.' );
        }

        return $role instanceof \Acl\iRole ? $role->getRoleId() : $role;
    }

    /**
     * Return correct resource id.
     * 
     * @param \Acl\iResource | string $resource
     * @return string
     */
    public function getResourceId( $resource )
    {
        if ( is_object( $resource ) && !($resource instanceof \Acl\iResource) )
        {
            throw new \Acl\Exception( 'Resource must be iResource implemented object, instance of ' . get_class( $resource ) . ' given.' );
        }

        if( is_array( $resource ) || is_resource( $resource ) )
        {
            throw new \Acl\Exception( 'Resource must be an string or integer, ' . gettype( $resource ) . ' given.' );
        }

        return $resource instanceof \Acl\iResource ? $resource->getResourceId() : $resource;
    }

}
