use strict;
use Test::More tests => 2;

use Net::SSL;

my $sock;
eval {
	$sock = Net::SSL->new(
		PeerAddr => '127.0.0.1',
		PeerPort => 443,
		Timeout  => 3,
	);
};

my $test_name = 'Net::SSL->new';
if ($@) {
	my $fail = $@;
	if ($fail =~ /\AConnect failed: connect: \b/i) {
		pass( "$test_name - expected failure" );
	}
	else {
		fail( "$test_name" );
		diag( $fail );
	}
}
else {
	ok( defined $sock, $test_name );
}

SKIP: {
	skip( "nothing listening on localhost:443", 1 )
		unless defined $sock;

	is( ref($sock), 'Net::SSL', 'blessed socket' );
}
