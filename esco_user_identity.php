<?php

/**
 * New user identity
 *
 * Populates a new user's default identity from LDAP on their first visit.
 *
 * This plugin requires that a working public_ldap directory be configured.
 *
 * @author Kris Steinhoff
 * @license GNU GPLv3+
 */

use EscoUserIdentity\LdapBackend;

class esco_user_identity extends rcube_plugin
{

    private $ldap;

    function init()
    {
        $this->add_hook('user_create', array($this, 'lookup_user_name'));
        $this->add_hook('login_after', array($this, 'login_after'));
        $this->add_hook('refresh_user', array($this, 'refresh_user'));
    }

    function lookup_user_name($args)
    {
        if (!$this->init_ldap($args['host'])) {
            return $args;
        }

        $results = $this->ldap->search('*', $args['user'], true);
        if (count($results->records) != 1) {
            return $args;
        }

        $record = $results->records[0];

        $args['user_name'] = $this->firstValue($record['name'] ?? null);
        $args['email_list'] = $this->collectEmailAliases($record);
        $args = $this->applyPrimaryEmail($args, $record);
        $args = $this->applyAlias($args, $record);

        return $args;
    }

    /**
     * LDAP attributes come back either as a scalar or an array of values -
     * normalize to a single value (the first one).
     */
    private function firstValue($value)
    {
        return is_array($value) ? ($value[0] ?? null) : $value;
    }

    /**
     * Fill in user_email from LDAP, but only if it isn't already set.
     */
    private function applyPrimaryEmail(array $args, array $record): array
    {
        $email = $this->firstValue($record['email'] ?? null);

        if (!$args['user_email'] && $email && strpos($email, '@')) {
            $args['user_email'] = rcube_utils::idn_to_ascii($email);
        }

        return $args;
    }

    /**
     * Fill in an alias from a configurable LDAP attribute
     * (esco_user_identity_alias), if that setting is used.
     */
    private function applyAlias(array $args, array $record): array
    {
        $alias_col = rcmail::get_instance()->config->get('esco_user_identity_alias');

        if ($alias_col && !empty($record[$alias_col])) {
            $args['alias'] = $this->firstValue($record[$alias_col]);
        }

        return $args;
    }

    /**
     * Collect every "email"/"email:*" LDAP attribute (qualified multi-valued
     * email aliases) into a flat list.
     */
    private function collectEmailAliases(array $record): array
    {
        $email_list = [];

        foreach (array_keys($record) as $key) {
            if (!preg_match('/^email($|:)/', $key)) {
                continue;
            }

            foreach ((array) $record[$key] as $alias) {
                if (strpos($alias, '@')) {
                    $email_list[] = rcube_utils::idn_to_ascii($alias);
                }
            }
        }

        return $email_list;
    }

    function login_after($args)
    {
        $this->load_config();

        // on récupère la liste des attributs utilisateurs à récupérer du ldap
        $user_fields = rcmail::get_instance()->config->get('esco_user_identity_complete_user_fields');
        // si cette liste est définie on récupère les attributs du ldap pour les ajouter à la définiton du user
        if (!empty($user_fields)) {
            if ($this->init_ldap('')) {
                $results = $this->ldap->search('*', rcmail::get_instance()->user->data['username'], 1);
                if (count($results->records) == 1) {
                    // on ajoute les attributs utilisateur
                    foreach ($user_fields as $attr) {
                        $user_attr = strtolower($attr);
                        $val = $results->records[0]['_raw_attrib'][$user_attr];
                        if (!empty($val)) {
                            rcmail::get_instance()->user->data[$user_attr] = $val;
                        }
                    }
                    rcmail::get_instance()->user->data['esco_user_inited'] = 'DONE';
                }
            }
        }

        $_SESSION['user_data'] = rcmail::get_instance()->user->data;
        if ($this->ldap) {
            $this->ldap->user = rcmail::get_instance()->user;
        }

        return $args;
    }

    function refresh_user($args){
        return $this->login_after($args);
    }

    private function init_ldap($host)
    {
        if ($this->ldap) {
            return $this->ldap->ready;
        }

        $this->load_config();

        $addressbook = rcmail::get_instance()->config->get('esco_user_identity_addressbook');
        $ldap_config = (array)rcmail::get_instance()->config->get('esco_ldap');
        $match = rcmail::get_instance()->config->get('esco_user_identity_match');

        if (empty($addressbook) || empty($match) || empty($ldap_config[$addressbook])) {
            return false;
        }

        $this->ldap = new LdapBackend(
            $ldap_config[$addressbook],
            rcmail::get_instance()->config->get('ldap_debug'),
            rcmail::get_instance()->config->mail_domain($host),
            $match);

        return $this->ldap->ready;
    }
}
