package Net::SSL;

# $Id: SSL.pm,v 1.5 1998/01/13 22:09:09 aas Exp $

use strict;
use vars qw(@ISA $VERSION);
$VERSION = sprintf("%d.%02d", q$Revision: 1.5 $ =~ /(\d+)\.(\d+)/);

require IO::Socket;
@ISA=qw(IO::Socket::INET);

require Crypt::SSLeay;

sub _default_context
{
    require Crypt::SSLeay::MainContext;
    Crypt::SSLeay::MainContext::main_ctx();
}

sub configure
{
    my($self, $arg) = @_;
    *$self->{'ssl_ctx'} = delete $arg->{SSL_Context} || _default_context();
    $self->SUPER::configure($arg);
}

sub connect
{
    my $self = shift;
    return unless $self->SUPER::connect(@_);
    my $ssl = Crypt::SSLeay::Conn->new(*$self->{'ssl_ctx'}, $self);
    if ($ssl->connect <= 0) {
	# XXX should obtain the real SSLeay error message
	$self->_error("SSL negotiation failed");
	return;
    }
    *$self->{'ssl_ssl'} = $ssl;
    $self;
}

sub accept
{
    die "NYI";
}

# Delegate these calls to the Crypt::SSLeay::Conn object
sub get_peer_certificate { *{shift()}->{'ssl_ssl'}->get_peer_certificate(@_) }
sub get_shared_ciphers   { *{shift()}->{'ssl_ssl'}->get_shared_ciphers(@_) }
sub get_cipher           { *{shift()}->{'ssl_ssl'}->get_cipher(@_) }

sub ssl_context
{
    my $self = shift;
    *$self->{'ssl_ctx'};
}

sub read
{
    my $self = shift;
    *$self->{'ssl_ssl'}->read(@_);
}

sub write
{
    my $self = shift;
    *$self->{'ssl_ssl'}->write(@_);
}

*sysread  = \&read;
*syswrite = \&write;

sub print
{
    my $self = shift;
    # should we care about $, and $\??
    # I think it is too expensive...
    $self->write(join("", @_));
}

sub printf
{
    my $self = shift;
    my $fmt  = shift;
    $self->write(sprintf($fmt, @_));
}


sub getchunk
{
    my $self = shift;
    my $buf = '';  # warnings
    my $n = $self->read($buf, 32*1024);
    return unless defined $n;
    $buf;
}

# In order to implement these we will need to add a buffer in $self.
# Is it worth it?
sub getc     { shift->_unimpl("getc");     }
sub ungetc   { shift->_unimpl("ungetc");   }
sub getline  { shift->_unimpl("getline");  }
sub getlines { shift->_unimpl("getlines"); }

# XXX: no way to disable <$sock>??  (tied handle perhaps?)

sub _unimpl
{
    my($self, $meth) = @_;
    die "$meth not implemented for Net::SSL sockets";
}

1;
