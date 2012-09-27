#!/usr/bin/perl -w

use strict;
use warnings;
use Locale::gettext;
use File::Basename;
use POSIX qw(setlocale);
use Time::HiRes qw(time);
use POSIX qw(mktime);
use Nagios::Plugin ;
use LWP::UserAgent;
use HTTP::Request;
use HTTP::Status;
use IO::Socket;

use Data::Dumper;

sub get_old_timestamp {
	my $cn=shift;
	my $file="/tmp/.$cn.value";
	return (stat($file))[9];
}
sub get_old_value {
	my $cn=shift;
	my $file="/tmp/.$cn.value";
	open (MYFILE, "<$file");
	my $value = <MYFILE>;
	close (MYFILE);
	return $value;
}
sub set_old_value {
	my $cn=shift;
	my $value=shift;
	my $file="/tmp/.$cn.value";
	open (MYFILE, ">$file");
	print MYFILE $value;
	close (MYFILE);
}

my $PROGNAME = basename($0);
'$Revision: 1.0 $' =~ /^.*(\d+\.\d+) \$$/;  # Use The Revision from RCS/CVS/SVN
my $VERSION = $1;

my $DEBUG = 0;
my $TIMEOUT = 9;

# i18n :
setlocale(LC_MESSAGES, '');
textdomain('nagios-plugins-perl');


my $np = Nagios::Plugin->new(
	version => $VERSION,
	blurb => _gt('Plugin to check HAProxy HTTP codes via stats url/socket'),
	usage => "Usage: %s [ -v|--verbose ]  -u <url> [-t <timeout>] [-U <username>] [-P <password>] [-b] [-f] [-s <show_only>] [--bw]",
	timeout => $TIMEOUT+1
);
$np->add_arg (
	spec => 'debug|d',
	help => _gt('Debug level'),
	default => 0,
);
$np->add_arg (
	spec => 'frontends|f',
	help => _gt('Show frontends'),
	default => 0,
);
$np->add_arg (
	spec => 'backends|b',
	help => _gt('Show backends'),
	default => 0,
);
$np->add_arg (
	spec => 'bw',
	help => _gt('Show traffic in place of HTTP codes'),
	default => 0,
);
$np->add_arg (
	spec => 'username|U=s',
	help => _gt('Username for HTTP Auth'),
	required => 0,
);
$np->add_arg (
	spec => 'password|P=s',
	help => _gt('Password for HTTP Auth'),
	required => 0,
);
$np->add_arg (
	spec => 'url|u=s',
	help => _gt('URL of the HAProxy csv statistics page HTTP or unix Socket.'),
	required => 1,
);
$np->add_arg (
	spec => 'show-only|s=s',
	help => _gt('Show only this backends/frontends (comma separarated)'),
	default => "",
);

$np->getopts;

$DEBUG = $np->opts->get('debug');
my $show_frontends = $np->opts->get('frontends');
my $show_backends = $np->opts->get('backends');
my $show_traffic = $np->opts->get('bw');
my $verbose = $np->opts->get('verbose');
my $username = $np->opts->get('username');
my $password = $np->opts->get('password');
my $url = $np->opts->get('url');
my @showonly = split(',',$np->opts->get('show-only'));

# Create a LWP user agent object:
my $ua = new LWP::UserAgent(
	'env_proxy' => 0,
	'timeout' => $TIMEOUT,
	);
$ua->agent(basename($0));

# Workaround for LWP bug :
$ua->parse_head(0);

# For csv data
my $stats="";

if ( $url =~ /^http/ ) {
	if ( defined($ENV{'http_proxy'}) ) {
		# Normal http proxy :
		$ua->proxy(['http'], $ENV{'http_proxy'});
		# Https must use Crypt::SSLeay https proxy (to use CONNECT method instead of GET)
		$ENV{'HTTPS_PROXY'} = $ENV{'http_proxy'};
	}
	# Build and submit an http request :
	my $request = HTTP::Request->new('GET', $url);
	# Authenticate if username and password are supplied
	if ( defined($username) && defined($password) ) {
		$request->authorization_basic($username, $password);
	}
	my $http_response = $ua->request( $request );

	if ( $http_response->is_error() ) {
		my $err = $http_response->code." ".status_message($http_response->code)." (".$http_response->message.")";
		$np->add_message(CRITICAL, _gt("HTTP error: ").$err );
	} elsif ( ! $http_response->is_success() ) {
		my $err = $http_response->code." ".status_message($http_response->code)." (".$http_response->message.")";
		$np->add_message(CRITICAL, _gt("Internal error: ").$err );
	}
	if ( $http_response->is_success() ) {
		$stats = $http_response->content;
	}

}elsif ( $url =~ /^\// ) {
	my $sock = new IO::Socket::UNIX (
		Peer => "$url",
		Type => SOCK_STREAM,
		Timeout => 1);
	if ( !$sock ) {
		my $err = "Can't connect to unix socket";
		$np->add_message(CRITICAL, _gt("Internal error: ").$err );
	}else{
		print $sock "show stat\n";
		while(my $line = <$sock>){
			$stats.=$line;
		}
	}
}else {
	my $err = "Can't detect socket type";
	$np->add_message(CRITICAL, _gt("Internal error: ").$err );
}

my ($status, $message) = $np->check_messages();

if ( $status == OK && $stats ne "") {
	if ($DEBUG) {
		print "------------------===csv output===------------------\n";
		print "$stats\n";
		print "----------------------------------------------------\n";
	};

	my @fields = ();
	my @rows = split(/\n/,$stats);
	if ( $rows[0] =~ /#\ \w+/ ) {
		$rows[0] =~ s/#\ //;
		@fields = split(/\,/,$rows[0]);
	} else {
		$np->nagios_exit(UNKNOWN, _gt("Can't find csv header !") );
	}

	my %stats = ();
	for ( my $y = 1; $y < $#rows; $y++ ) {
		my @values = split(/\,/,$rows[$y]);
		if ( !defined($stats{$values[0]}) ) {
			$stats{$values[0]} = {};
		}
		if ( !defined($stats{$values[0]}{$values[1]}) ) {
			$stats{$values[0]}{$values[1]} = {};
		}
		for ( my $x = 2,; $x <= $#values; $x++ ) {
			# $stats{pxname}{svname}{valuename}
			$stats{$values[0]}{$values[1]}{$fields[$x]} = $values[$x];
		}
	}
	my $okMsg = '';
	foreach my $pxname ( keys(%stats) ) {
		foreach my $svname ( keys(%{$stats{$pxname}}) ) {
			if ( ( $stats{$pxname}{$svname}{'type'} eq 0 && $show_frontends ) || ( $stats{$pxname}{$svname}{'type'} eq 1 && $show_backends ) ) {
				my $type = lc($svname);
				if (@showonly && !grep(/^$pxname$/,@showonly) ) {
					next;
				}
				if ( $stats{$pxname}{$svname}{'hrsp_2xx'} eq '' ) {
					next;
				}
				my @wanted_values;
				my $uom;
				if ( $show_traffic ) {
					@wanted_values = ("bin","bout");
					$uom="bytes/s";
				}else{
					@wanted_values = ("hrsp_1xx","hrsp_2xx","hrsp_3xx","hrsp_4xx","hrsp_5xx");
					$uom="rps/s";
				}
				foreach my $valkey (@wanted_values) {
					my $deltatime = time - get_old_timestamp("$type-$pxname-$valkey");
					my $oldvalue  = get_old_value("$type-$pxname-$valkey");
					my $value = $stats{$pxname}{$svname}{$valkey};
					set_old_value("$type-$pxname-$valkey", $value );
					my $value_per_sec = int(( $value - $oldvalue ) / $deltatime);
					$np->add_perfdata(
						'label' => "$type-$pxname-$valkey",
						'value' => $value_per_sec,
						'uom' => $uom,
					);
				}
			}
		}
	}

	($status, $message) = $np->check_messages('join' => ' ');

	if ( $status == OK ) {
		$message = $okMsg;

	}

}

$np->nagios_exit($status, $message );


sub _gt {
	return gettext($_[0]);
}
