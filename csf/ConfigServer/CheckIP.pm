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
package ConfigServer::CheckIP;

use strict;
use lib '/usr/local/csf/lib';
use Carp;
use Net::IP;
use ConfigServer::Config;

use Exporter qw(import);
our $VERSION     = 1.03;
our @ISA         = qw(Exporter);
our @EXPORT_OK   = qw(checkip cccheckip validate_port validate_uid valid_adport_prefix);

my $ipv4reg = ConfigServer::Config->ipv4reg;
my $ipv6reg = ConfigServer::Config->ipv6reg;

# end main
###############################################################################
# start checkip
sub checkip {
	my $ipin = shift;
	my $ret = 0;
	my $ipref = 0;
	my $ip;
	my $cidr;
	if (ref $ipin) {
		($ip,$cidr) = split(/\//,${$ipin});
		$ipref = 1;
	} else {
		($ip,$cidr) = split(/\//,$ipin);
	}
	my $testip = $ip;

	if ($cidr ne "") {
		unless ($cidr =~ /^\d+$/) {return 0}
	}

	if ($ip =~ /^$ipv4reg$/) {
		$ret = 4;
		if ($cidr) {
			unless ($cidr >= 1 && $cidr <= 32) {return 0}
		}
		if ($ip eq "127.0.0.1") {return 0}
	}

	if ($ip =~ /^$ipv6reg$/) {
		$ret = 6;
		if ($cidr) {
			unless ($cidr >= 1 && $cidr <= 128) {return 0}
		}
		$ip =~ s/://g;
		$ip =~ s/^0*//g;
		if ($ip == 1) {return 0}
		if ($ipref) {
			eval {
				local $SIG{__DIE__} = undef;
				my $netip = Net::IP->new($testip);
				my $myip = $netip->short();
				if ($myip ne "") {
					if ($cidr eq "") {
						${$ipin} = $myip;
					} else {
						${$ipin} = $myip."/".$cidr;
					}
				}
			};
			if ($@) {return 0}
		}
	}

	return $ret;
}
# end checkip
###############################################################################
# start cccheckip
sub cccheckip {
	my $ipin = shift;
	my $ret = 0;
	my $ipref = 0;
	my $ip;
	my $cidr;
	if (ref $ipin) {
		($ip,$cidr) = split(/\//,${$ipin});
		$ipref = 1;
	} else {
		($ip,$cidr) = split(/\//,$ipin);
	}
	my $testip = $ip;

	if ($cidr ne "") {
		unless ($cidr =~ /^\d+$/) {return 0}
	}

	if ($ip =~ /^$ipv4reg$/) {
		$ret = 4;
		if ($cidr) {
			unless ($cidr >= 1 && $cidr <= 32) {return 0}
		}
		if ($ip eq "127.0.0.1") {return 0}
		my $type;
		eval {
			local $SIG{__DIE__} = undef;
			my $netip = Net::IP->new($testip);
			$type = $netip->iptype();
		};
		if ($@) {return 0}
		if ($type ne "PUBLIC") {return 0}
	}

	if ($ip =~ /^$ipv6reg$/) {
		$ret = 6;
		if ($cidr) {
			unless ($cidr >= 1 && $cidr <= 128) {return 0}
		}
		$ip =~ s/://g;
		$ip =~ s/^0*//g;
		if ($ip == 1) {return 0}
		if ($ipref) {
			eval {
				local $SIG{__DIE__} = undef;
				my $netip = Net::IP->new($testip);
				my $myip = $netip->short();
				if ($myip ne "") {
					if ($cidr eq "") {
						${$ipin} = $myip;
					} else {
						${$ipin} = $myip."/".$cidr;
					}
				}
			};
			if ($@) {return 0}
		}
	}

	return $ret;
}
# end cccheckip
###############################################################################

###############################################################################
# start advanced-rule field validators
#
# Advanced rule fields (tcp|in|d=22|s=1.2.3.4) are interpolated into the command
# string that iptablescmd()/syscommand() build, so a field carrying shell
# metacharacters or a leading "-" must never get that far. These validators are
# allow-lists: anything not explicitly permitted is refused, and the caller
# reports the rule instead of silently producing no iptables rule.
my $MAX_FIELD_LENGTH  = 64;
my $MAX_PREFIX_LENGTH = 128;

sub validate_port {
	my $port = shift;
	return 0 unless defined $port and length $port;
	return 0 if length $port > $MAX_FIELD_LENGTH;

	# "/" is permitted for the iptables ICMP "type/code" form. The first
	# character may not be "-", or the value reaches iptables as an option rather
	# than as the argument to --dport. A leading ":" stays legal for the
	# open-ended ":3000" range form. Anchored with \z so a trailing newline
	# cannot terminate the generated command early.
	return $port =~ m{\A[A-Za-z0-9_,:/][A-Za-z0-9_,:/-]*\z} ? 1 : 0;
}

sub validate_uid {
	my $uid = shift;
	return 0 unless defined $uid and length $uid;
	return 0 if length $uid > $MAX_FIELD_LENGTH;

	# The first character may not be "-", or the value reaches iptables as an
	# option rather than as the argument to --uid-owner.
	return $uid =~ m{\A[A-Za-z0-9_.][A-Za-z0-9_.-]*\z} ? 1 : 0;
}

sub valid_adport_prefix {
	my $prefix = shift;
	return 1 unless defined $prefix;
	return 0 if length $prefix > $MAX_PREFIX_LENGTH;

	# A leading ":" stays legal because a persisted csf.tempdyn entry may be a
	# bare compressed IPv6 address. The first character may not be "-", so that
	# neither the prefix nor a fused prefix+IP can reach iptables as an option.
	return $prefix =~ m{\A[A-Za-z0-9_,.:|=/][A-Za-z0-9_,.:|=/-]*\z} ? 1 : 0;
}
# end advanced-rule field validators
###############################################################################

1;