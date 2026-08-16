# #
#   @app                ConfigServer Security & Firewall (CSF)
#                       Login Failure Daemon (LFD)
#   @website            https://configserver.dev
#   @docs               https://docs.configserver.dev
#   @download           https://download.configserver.dev
#   @repo               https://github.com/Aetherinox/csf-firewall
#   @copyright          Copyright (C) 2025-2026 Aetherinox
#                       Copyright (C) 2006-2025 Jonathan Michaelson
#                       Copyright (C) 2006-2025 Way to the Web Ltd.
#   @license            GPLv3
#   @updated            02.12.2026
#   
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or (at
#   your option) any later version.
#   
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#   General Public License for more details.
#   
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, see <https://www.gnu.org/licenses>.
# #
## no critic (RequireUseWarnings, ProhibitExplicitReturnUndef, ProhibitMixedBooleanOperators, RequireBriefOpen)
# start main
package ConfigServer::URLGet;

use strict;
use lib '/usr/local/csf/lib';
use Fcntl qw(:DEFAULT :flock);
use Carp;
use IPC::Open3;
use ConfigServer::Config;

use Exporter qw(import);
our $VERSION     = 2.00;
our @ISA         = qw(Exporter);
our @EXPORT_OK   = qw();

my $agent = "ConfigServer";
my $option = 1;
my $proxy = "";

my $config = ConfigServer::Config->loadconfig();
my %config = $config->config();
$SIG{PIPE} = 'IGNORE';

# end main
###############################################################################
# start new
sub new {
	my $class = shift;
	$option = shift;
	$agent = shift;
	$proxy = shift;
	my $self = {};
	bless $self,$class;

	if ($option == 3) {
		return $self;
	}
	elsif ($option == 2) {
		eval ('use LWP::UserAgent;'); ##no critic
		if ($@) {return undef}
	}
	else {
		eval {
			local $SIG{__DIE__} = undef;
			eval ('use HTTP::Tiny;'); ##no critic
		};
	}

	return $self;
}
# end new
###############################################################################
# start urlget
sub urlget {
	my $self = shift;
	my $url = shift;
	my $file = shift;
	my $quiet = shift;
	my $status;
	my $text;

	if (!defined $url) {carp "url not specified"; return}

	if ($option == 3) {
		($status, $text) = &binget($url,$file,$quiet);
	}
	elsif ($option == 2) {
		($status, $text) = &urlgetLWP($url,$file,$quiet);
	}
	else {
		($status, $text) = &urlgetTINY($url,$file,$quiet);
	}
	return ($status, $text);
}
# end urlget
###############################################################################
# start urlgetTINY
sub urlgetTINY {
	my $url = shift;
	my $file = shift;
	my $quiet = shift;
	my $status = 0;
	my $timeout = 1200;
	if ($proxy eq "") {undef $proxy}
	my $ua = HTTP::Tiny->new(
		'agent' => $agent,
		'timeout' => 300,
		'proxy' => $proxy
		);
	my $res;
	my $text;
	($status, $text) = eval {
		local $SIG{__DIE__} = undef;
		local $SIG{'ALRM'} = sub {die "Download timeout after $timeout seconds"};
		alarm($timeout);
		if ($file) {
			local $|=1;
			my $expected_length;
			my $bytes_received = 0;
			my $per = 0;
			my $oldper = 0;
			open (my $OUT, ">", "$file\.tmp") or return (1, "Unable to open $file\.tmp: $!");
			flock ($OUT, LOCK_EX);
			binmode ($OUT);
			$res = $ua->request('GET', $url, {
				data_callback => sub {
					my($chunk, $res) = @_;
					$bytes_received += length($chunk);
					unless (defined $expected_length) {$expected_length = $res->{headers}->{'content-length'} || 0}
					if ($expected_length) {
						my $per = int(100 * $bytes_received / $expected_length);
						if ((int($per / 5) == $per / 5) and ($per != $oldper) and !$quiet) {
							print "...$per\%\n";
							$oldper = $per;
						}
					} else {
						unless ($quiet) {print "."}
					}
					print $OUT $chunk;
				}
			});
			close ($OUT);
			unless ($quiet) {print "\n"}
		} else {
			$res = $ua->request('GET', $url);
		}
		alarm(0);
		if ($res->{success}) {
			if ($file) {
				rename ("$file\.tmp","$file") or return (1, "Unable to rename $file\.tmp to $file: $!");
				return (0, $file);
			} else {
				return (0, $res->{content});
			}
		} else {
			my $reason = $res->{reason};
			if ($res->{status} == 599) {$reason = $res->{content}}
			($status, $text) = &binget($url,$file,$quiet,$reason);
			return ($status, $text);
		}
	};
	alarm(0);
	if ($@) {return (1, $@)}
	return ($status,$text);
}
# end urlgetTINY
###############################################################################
# start urlgetLWP
sub urlgetLWP {
	my $url = shift;
	my $file = shift;
	my $quiet = shift;
	my $status = 0;
	my $timeout = 300;
	my $ua = LWP::UserAgent->new;
	$ua->agent($agent);
	$ua->timeout(30);
	if ($proxy ne "") {$ua->proxy([ 'http', 'https' ], $proxy)}
#use LWP::ConnCache;
#my $cache = LWP::ConnCache->new;
#$cache->total_capacity([1]);
#$ua->conn_cache($cache);
	my $req = HTTP::Request->new(GET => $url);
	my $res;
	my $text;
	($status, $text) = eval {
		local $SIG{__DIE__} = undef;
		local $SIG{'ALRM'} = sub {die "Download timeout after $timeout seconds"};
		alarm($timeout);
		if ($file) {
			local $|=1;
			my $expected_length;
			my $bytes_received = 0;
			my $per = 0;
			my $oldper = 0;
			open (my $OUT, ">", "$file\.tmp") or return (1, "Unable to open $file\.tmp: $!");
			flock ($OUT, LOCK_EX);
			binmode ($OUT);
			$res = $ua->request($req,
				sub {
				my($chunk, $res) = @_;
				$bytes_received += length($chunk);
				unless (defined $expected_length) {$expected_length = $res->content_length || 0}
				if ($expected_length) {
					my $per = int(100 * $bytes_received / $expected_length);
					if ((int($per / 5) == $per / 5) and ($per != $oldper) and !$quiet) {
						print "...$per\%\n";
						$oldper = $per;
					}
				} else {
					unless ($quiet) {print "."}
				}
				print $OUT $chunk;
			});
			close ($OUT);
			unless ($quiet) {print "\n"}
		} else {
			$res = $ua->request($req);
		}
		alarm(0);
		if ($res->is_success) {
			if ($file) {
				rename ("$file\.tmp","$file") or return (1, "Unable to rename $file\.tmp to $file: $!");
				return (0, $file);
			} else {
				return (0, $res->content);
			}
		} else {
			($status, $text) = &binget($url,$file,$quiet,$res->message);
			return ($status, $text);
		}
	};
	alarm(0);
	if ($@) {
		return (1, $@);
	}
	if ($text) {
		return ($status,$text);
	} else {
		return (1, "Download timeout after $timeout seconds");
	}
}
# end urlget
###############################################################################
# start binget
sub binget {
	my $url = shift;
	my $file = shift;
	my $quiet = shift;
	my $errormsg = shift;
	my $url_for_output = _redact_key_from_text($url);

	# A URL containing a newline could smuggle extra directives into the stdin
	# formats used by _binget_command(), so refuse control characters before a
	# child process is ever spawned.
	if ($url =~ /[[:cntrl:]]/) {
		return (1, "Unable to download: the URL contains control characters");
	}

	my $fetch = _binget_command($url, $file);
	my @cmd = @{$fetch->{cmd}};
	if (@cmd) {
		my $cmd_for_output = join(" ", @cmd);
		my $run = _binget_run(\@cmd, $fetch->{stdin});
		if (length $run->{error}) {
			return (1, "Unable to download: unable to pass the URL to $cmd[0]: ".$run->{error});
		}
		my @output = @{$run->{output}};
		if ($file) {
			unless ($quiet and $option != 3) {
				print "Using fallback [$cmd_for_output]\n";
				print map { _redact_key_from_text($_) } @output;
			}
			if (-e "$file\.tmp") {
				rename ("$file\.tmp","$file") or return (1, "Unable to rename $file\.tmp to $file: $!");
				return (0, $file);
			} else {
				if ($option == 3) {
					my $output_for_error = join("", map { _redact_key_from_text($_) } @output);
					return (1, "Unable to download: $cmd_for_output '$url_for_output'".$output_for_error);
				} else {
					return (1, "Unable to download: ".$errormsg);
				}
			}
		} else {
			if (scalar @output > 0) {
				return (0, join("",@output));
			} else {
				if ($option == 3) {
					my $output_for_error = join("", map { _redact_key_from_text($_) } @output);
					return (1, "Unable to download: [$cmd_for_output '$url_for_output']".$output_for_error);
				} else {
					return (1, "Unable to download: ".$errormsg);
				}
			}
		}
	}
	if ($option == 3) {
		return (1, "Unable to download (CURL/WGET also not present, see csf.conf)");
	} else {
		return (1, "Unable to download (CURL/WGET also not present, see csf.conf): ".$errormsg);
	}
}

# Build the fallback fetch as an explicit argv list so that open3 can be called
# in list form and no /bin/sh is involved. This retires the shell-injection
# class outright rather than trying to quote around it, which is why the URL no
# longer needs the "'...'" wrapping it previously relied on to survive the
# shell.
#
# The URL is handed to the child on stdin rather than in argv, because callers
# embed credentials in it (RECAPTCHA_SECRET for the reCAPTCHA siteverify
# request, MM_LICENSE_KEY for the MaxMind downloads, blocklist API keys in lfd)
# and /proc/PID/cmdline is world readable. An argv URL therefore exposes those
# secrets to every local user, and to any process collector, for as long as the
# fetch runs. curl reads the URL from a --config file on stdin, wget from an
# --input-file URL list.
sub _binget_command {
	my $url = shift;
	my $file = shift;

	my @cmd;
	my $stdin = "";
	if (-e $config{CURL}) {
		# Certificate validation is deliberately NOT disabled here. Upstream
		# passes -k on this path, which lets anyone able to intercept the
		# connection replace the payload - including a GLOBAL_ALLOW/GLOBAL_DENY
		# feed whose contents lfd applies as root.
		@cmd = $file ? ($config{CURL}, "-Lf", "-m", "120", "-o", "$file\.tmp") : ($config{CURL}, "-sLf", "-m", "120");

		# "-g" turns off curl's URL globbing, so that "{}" and "[]" in a URL are
		# fetched literally instead of being expanded into a different, or into
		# more than one, request. The Perl backends never glob, so this also
		# makes the fallback fetch the same URL they would.
		push @cmd, "-g", "-K", "-";
		$stdin = 'url = "'._escape_curl_config_value($url).'"'."\n";
	}
	elsif (-e $config{WGET}) {
		@cmd = $file ? ($config{WGET}, "-T", "120", "-O", "$file\.tmp") : ($config{WGET}, "-qT", "120", "-O-");
		push @cmd, "-i", "-";
		$stdin = "$url\n";
	}

	return {cmd => \@cmd, stdin => $stdin};
}

sub _binget_run {
	my $cmd = shift;
	my $stdin = shift;

	my ($childin, $childout);
	my $cmdpid = open3($childin, $childout, $childout, @{$cmd});

	# The URL travels here, on stdin, and must be flushed and the pipe closed
	# before the child will act on it. $SIG{PIPE} is ignored package-wide (see
	# the top of this file), so a child that died early surfaces as a failed
	# print rather than a signal.
	my $wrote = print {$childin} $stdin;
	my $error = $wrote ? "" : "$!";
	close($childin);

	my @output = <$childout>;
	waitpid ($cmdpid, 0);

	return {output => \@output, error => $error};
}

sub _escape_curl_config_value {
	my $value = shift;

	# curl's --config parser understands \\ and \" inside a double-quoted value,
	# so both characters have to be escaped for the URL to survive verbatim.
	$value =~ s/([\\"])/\\$1/g;

	return $value;
}

sub _redact_key_from_text {
	my $text = shift;
	return $text if !defined $text;

	# Redact both "key=" and "secret=" so the reCAPTCHA siteverify secret
	# (RECAPTCHA_SECRET) is not leaked into lfd_messenger.log or other error
	# output.
	$text =~ s/([?&])(key|secret)=[^&\s'"]*/${1}${2}=REDACTED/ig;

	return $text;
}
# end binget
###############################################################################
1;