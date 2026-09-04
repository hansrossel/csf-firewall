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
package ConfigServer::Slurp;

use strict;
use lib '/usr/local/csf/lib';
use Fcntl qw(:DEFAULT :flock);
use Carp;

use Exporter qw(import);
our $VERSION     = 1.02;
our @ISA         = qw(Exporter);
our @EXPORT_OK   = qw(slurp);

# Record separator for every csf configuration file. Deliberately byte
# oriented: slurp() returns the raw bytes of the file without decoding them, so
# a codepoint above 255 in this class makes the regex engine apply Unicode
# rules to a byte string. With NEL (\x85) in the class that matched the second
# byte of every UTF-8 sequence whose codepoint is congruent to 5 mod 64 --
# U+0085, U+0105, U+0145 and so on all encode as <lead> 0x85 -- so a single
# accented character in a csf.allow or csf.deny comment split the entry in two
# and the tail was read back as a further entry. \x{2028} and \x{2029} carried
# the same defect for their own byte sequences.
#
# The set kept here is the one the kernel, the shell and every editor actually
# write: CRLF, CR, LF, VT and FF. valid_comment() in csf.pl guards written
# comments against exactly this regex, so narrowing it here without narrowing
# there would let a separator through that this parser still splits on.
our $slurpreg = qr/(?>\x0D\x0A?|[\x0A-\x0C])/;
our $cleanreg = qr/(\r)|(\n)|(^\s+)|(\s+$)/;

# end main
###############################################################################
# start slurp
sub slurp {
	my $file = shift;
	if (-e $file) {
		sysopen (my $FILE, $file, O_RDONLY) or carp "*Error* Unable to open [$file]: $!";
		flock ($FILE, LOCK_SH) or carp "*Error* Unable to lock [$file]: $!";
		my $text = do {local $/; <$FILE>};
		close ($FILE);
		return split(/$slurpreg/,$text);
	} else {
		carp "*Error* File does not exist: [$file]";
	}

	return;
}
# end slurp
###############################################################################
# start slurpreg
sub slurpreg {
	return $slurpreg;
}
# end slurpreg
###############################################################################
# start cleanreg
sub cleanreg {
	return $cleanreg;
}
# end cleanreg
###############################################################################

1;