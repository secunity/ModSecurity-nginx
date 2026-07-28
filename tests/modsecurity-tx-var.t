#!/usr/bin/perl

# Tests for the modsecurity_tx_var directive, which publishes an nginx
# value into the ModSecurity TX collection as TX:<key>.
#
# $http_x_ja4 is used as the nginx source variable: it exercises the same
# code path as e.g. $http_ssl_ja4 from a TLS fingerprinting module, without
# requiring TLS in the test suite.

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;
        root         %%TESTDIR%%;

        # Inherited by locations that do not define their own tx vars.
        modsecurity_tx_var site s1;

        location /ja4 {
            modsecurity on;
            modsecurity_tx_var ssl_ja4 $http_x_ja4;
            modsecurity_rules '
                SecRuleEngine On
                SecRule TX:ssl_ja4 "@streq blockme" "id:900,phase:1,log,deny,status:403"
            ';
        }

        location /upper {
            modsecurity on;
            modsecurity_tx_var ssl_ja4 $http_x_ja4;
            modsecurity_rules '
                SecRuleEngine On
                SecRule TX:SSL_JA4 "@streq blockme" "id:901,phase:1,log,deny,status:403"
            ';
        }

        location /static {
            modsecurity on;
            modsecurity_tx_var env prod;
            modsecurity_rules '
                SecRuleEngine On
                SecRule TX:env "@streq prod" "id:902,phase:1,log,deny,status:403"
            ';
        }

        location /multi {
            modsecurity on;
            modsecurity_tx_var ssl_ja4 $http_x_ja4;
            modsecurity_tx_var tenant $http_x_tenant;
            modsecurity_rules '
                SecRuleEngine On
                SecRule TX:ssl_ja4 "@streq blockme" "id:903,phase:1,log,deny,status:403,chain"
                    SecRule TX:tenant "@streq acme"
            ';
        }

        location /inherited {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule TX:site "@streq s1" "id:904,phase:1,log,deny,status:403"
            ';
        }

        location /override {
            modsecurity on;
            modsecurity_tx_var other x;
            modsecurity_rules '
                SecRuleEngine On
                SecRule TX:site "@streq s1" "id:905,phase:1,log,deny,status:403"
            ';
        }

        # Value is used in a phase 2 rule, proving it survives past phase 1.
        location /phase2 {
            modsecurity on;
            modsecurity_tx_var ssl_ja4 $http_x_ja4;
            modsecurity_rules '
                SecRuleEngine On
                SecRule TX:ssl_ja4 "@streq blockme" "id:906,phase:2,log,deny,status:403"
            ';
        }
    }
}
EOF

$t->write_file('ja4', 'body');
$t->write_file('upper', 'body');
$t->write_file('static', 'body');
$t->write_file('multi', 'body');
$t->write_file('inherited', 'body');
$t->write_file('override', 'body');
$t->write_file('phase2', 'body');

$t->run();
$t->plan(9);

###############################################################################

# The nginx variable reaches the rules as TX:ssl_ja4 and the rule matches.
like(get('/ja4', 'X-JA4: blockme'), qr/ 403 /, 'tx var set: rule matches, blocked');

# Same var, different value: rule does not match.
like(get('/ja4', 'X-JA4: allowme'), qr/ 200 /, 'tx var set to other value: not blocked');

# Header absent => nginx var empty => TX:ssl_ja4 never set => no match.
like(get('/ja4'), qr/ 200 /, 'nginx var empty: tx var not set, not blocked');

# TX keys are case insensitive: rule reads TX:SSL_JA4, directive set ssl_ja4.
like(get('/upper', 'X-JA4: blockme'), qr/ 403 /, 'tx key lookup is case insensitive');

# A static (non-variable) value is also published.
like(get('/static'), qr/ 403 /, 'static value published to tx');

# Two directives in one location: both vars available to a chained rule.
like(get('/multi', 'X-JA4: blockme', 'X-Tenant: acme'), qr/ 403 /,
    'multiple tx vars available in one transaction');

# Server-level directive is inherited by a location with no tx vars of its own.
like(get('/inherited'), qr/ 403 /, 'server-level tx var inherited by location');

# A location defining its own tx vars replaces (does not append to) the
# server-level list, so TX:site is not set there.
like(get('/override'), qr/ 200 /, 'location tx vars override server-level list');

# The value persists into later phases.
like(get('/phase2', 'X-JA4: blockme'), qr/ 403 /, 'tx var visible to phase 2 rules');

###############################################################################

sub get {
    my ($uri, @headers) = @_;
    my $req = "GET $uri HTTP/1.0" . CRLF . "Host: localhost" . CRLF;
    $req .= $_ . CRLF for @headers;
    $req .= CRLF;
    return http($req);
}

###############################################################################
