<?php

namespace EscoUserIdentity;

class LdapBackend extends \rcube_ldap
{
    function __construct($p, $debug, $mail_domain, $search)
    {
        parent::__construct($p, $debug, $mail_domain);
        $this->prop['search_fields'] = (array) $search;
    }
}
