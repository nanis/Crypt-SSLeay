# 00-basic.t

use Test::More tests => 14;

my $PROXY_ADDR_PORT = 'localhost:3128';

BEGIN {
    use_ok( 'Crypt::SSLeay' );
    use_ok( 'Crypt::SSLeay::CTX' );
    use_ok( 'Crypt::SSLeay::Conn' );
    use_ok( 'Crypt::SSLeay::Err' );
    use_ok( 'Crypt::SSLeay::MainContext', 'main_ctx' );
    use_ok( 'Crypt::SSLeay::X509' );
    use_ok( 'Net::SSL' );
}

SKIP: {
    skip( 'Test::Pod not installed on this system', 2 )
        unless do {
            eval "use Test::Pod";
            $@ ? 0 : 1;
        };

    pod_file_ok( 'SSLeay.pm' );
    pod_file_ok( 'lib/Net/SSL.pm' );
}

SKIP: {
    skip( 'Test::Pod::Coverage not installed on this system', 2 )
        unless do {
            eval "use Test::Pod::Coverage";
            $@ ? 0 : 1;
        };
    pod_coverage_ok( 'Crypt::SSLeay', 'Crypt-SSLeay POD coverage is go!' );
    pod_coverage_ok( 'Net::SSL', 'Net::SSL POD coverage is go!' );
}

my $ctx = main_ctx();
is(ref($ctx), 'Crypt::SSLeay::CTX', 'we have a context');

sub mysub {
    my $hr = shift;
    local $ENV{HTTPS_PROXY} = $PROXY_ADDR_PORT;
    my $sock = Net::SSL->new(
        PeerAddr => 'rt.cpan.org',
        PeerPort => 443,
        Timeout  => 10,
    );
}

my $test_name = 'connect through proxy';
Net::SSL::send_useragent_to_proxy(0);
eval { mysub( {chobb => 'schoenmaker'} ) };
my $err = $@;
if (length $err == 0) {
    pass( $test_name );
    $err = 0;
}
else {
    if ($err =~ /^proxy connect failed: proxy connect to $PROXY_ADDR_PORT failed: / ) {
        pass( "$test_name - no proxy available" );
    }
    else {
        fail( "$test_name - untrapped error" );
        diag($@);
    }
    $err = 1;
}

SKIP: {
    skip( "no proxy found at $PROXY_ADDR_PORT", 1 )
        if $err;

    Net::SSL::send_useragent_to_proxy(1);
    my $test_name = 'connect through proxy, forward user agent';
    eval { mysub( {chobb => 'schoenmaker'} ) };
    $err = $@;

    TODO: {
        local $TODO = "stack walk broken";
        is( $err, '', "can forward useragent string to proxy" );
    }
}
