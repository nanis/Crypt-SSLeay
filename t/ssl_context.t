print "1..1\n";

use Crypt::SSLeay::Context qw(ssl_ctx);

print "not " unless ssl_ctx() =~ /CTX/;
print "ok 1\n";

