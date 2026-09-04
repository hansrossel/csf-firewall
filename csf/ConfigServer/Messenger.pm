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
package ConfigServer::Messenger;

use strict;
use lib '/usr/local/csf/lib';
use Fcntl qw(:DEFAULT :flock);
use File::Copy;
use JSON::Tiny;
use IO::Socket::INET;
use Net::CIDR::Lite;
use Net::IP;
use IPC::Open3;
# Imported with an empty list: POSIX exports several hundred names by default
# and this module only needs setuid/setgid, called fully qualified.
use POSIX ();
use ConfigServer::Config;
use ConfigServer::CheckIP qw(checkip);
use ConfigServer::Logger qw(logfile);
use ConfigServer::URLGet;
use ConfigServer::Slurp qw(slurp);
use ConfigServer::GetIPs qw(getips);
use ConfigServer::GetEthDev;

use Exporter qw(import);
our $VERSION     = 3.00;
our @ISA         = qw(Exporter);
our @EXPORT_OK   = qw();

my $slurpreg = ConfigServer::Slurp->slurpreg;
my $cleanreg = ConfigServer::Slurp->cleanreg;

my $config = ConfigServer::Config->loadconfig();
my %config = $config->config();
my $ipv4reg = ConfigServer::Config->ipv4reg;
my $ipv6reg = ConfigServer::Config->ipv6reg;

my $childproc;
my $hostname;

my %ips;
my $ipscidr6;
my %sslcerts;
my %sslkeys;
my %ssldomains;
my @ssldomainkeys;
my $webserver = "apache";
my $sslhost;
my $sslcert;
my $sslkey;
my $sslca;
my $osslcert;
my $osslkey;
my $osslca;
my $sslaliases;
my $litestart = 0;
my $ssldir = "/var/lib/csf/ssl/";
my $phphandler;
my $version = 1;
my $serverroot;

# end main
###############################################################################
# start init
sub init {
	my $class = shift;
	$version = shift;
	my $self = {};
	bless $self,$class;

	if (-e "/proc/sys/kernel/hostname") {
		open (my $IN, "<", "/proc/sys/kernel/hostname");
		flock ($IN, LOCK_SH);
		$hostname = <$IN>;
		chomp $hostname;
		close ($IN);
	} else {
		$hostname = "unknown";
	}
	if ($version == 1) {
		if ($config{MESSENGER6}) {
			eval('use IO::Socket::INET6;'); ##no critic
			if ($@) {$config{MESSENGER6} = "0"}
		}
		$ipscidr6 = Net::CIDR::Lite->new;
		&getethdev;
		foreach my $ip (split(/,/,$config{RECAPTCHA_NAT})) {
			$ip =~ s/\s*//g;
			$ips{$ip} = 1;
		}
	}
	elsif ($version == 2) {
	}
	elsif ($version == 3) {
		mkdir $ssldir;
		mkdir $ssldir."certs/";
		mkdir $ssldir."keys/";
		mkdir $ssldir."ca/";
	}
	
	return $self;
}
# end init
###############################################################################
# start start
sub start {
	my $self = shift;
	my $port = shift;
	my $user = shift;
	my $type = shift;
	my $status;
	my $reason;
	if ($version == 1) {
		($status,$reason) = &messenger($port, $user, $type);
	}
	elsif ($version == 2) {
		($status,$reason) = &messengerv2();
	}
	elsif ($version == 3) {
		($status,$reason) = &messengerv3();
	}
	
	return ($status,$reason);
}
# end start
###############################################################################
# start messenger
sub messenger {
	my $port = shift;
	my $user = shift;
	my $type = shift;
	my $oldtype = $type;
	my $server;
	my %sslcerts;
	my %sslkeys;

	$SIG{CHLD} = 'IGNORE';
	$SIG{INT} = \&childcleanup;
	$SIG{TERM} = \&childcleanup;
	$SIG{HUP} = \&childcleanup;
	$SIG{__DIE__} = sub {&childcleanup(@_);};
	$0 = "lfd $type messenger";
	$childproc = "Messenger ($type)";

	if ($type eq "HTTPS") {
		eval {
			local $SIG{__DIE__} = undef;
			require IO::Socket::SSL;
			import IO::Socket::SSL;
		};

		my $start = 0;
		my $sslhost;
		my $sslcert;
		my $sslkey;
		my $sslaliases;
		my %messengerports;
		foreach my $serverports (split(/\,/,$config{MESSENGER_HTTPS_IN})) {$messengerports{$serverports} = 1}
		foreach my $file (glob($config{MESSENGER_HTTPS_CONF})) {
			if (-e $file) {
				foreach my $line (slurp($file)) {
					$line =~ s/\'|\"//g;
					if ($line =~ /^\s*<VirtualHost\s+[^\>]+>/) {
						$start = 1;
					}
					if ($webserver eq "apache" and $start) {
						if ($line =~ /\s*ServerName\s+(\w+:\/\/)?([a-zA-Z0-9\.\-]+)(:\d+)?/) {$sslhost = $2}
						if ($line =~ /\s*ServerAlias\s+(.*)/) {$sslaliases .= " ".$1}
						if ($line =~ /\s*SSLCertificateFile\s+(\S+)/) {
							my $match = $1;
							if (-e $match) {$sslcert = $match}
						}
						if ($line =~ /\s*SSLCertificateKeyFile\s+(\S+)/) {
							my $match = $1;
							if (-e $match) {$sslkey = $match}
						}
					}

					if (($webserver eq "apache" and $line =~ /^\s*<\/VirtualHost\s*>/)) {
						$start = 0;
						if ($sslhost ne "" and !checkip($sslhost) and $sslcert ne "") {
							$sslcerts{$sslhost} = $sslcert;
							if ($sslkey eq "") {$sslkey = $sslcert}
							$sslkeys{$sslhost} = $sslkey;
							foreach my $alias (split(/\s+/,$sslaliases)) {
								if ($alias eq "") {next}
								if (checkip($alias)) {next}
								if ($alias =~ /^[a-zA-Z0-9\.\-]+$/) {
									if ($config{MESSENGER_HTTPS_SKIPMAIL} and $alias =~ /^mail\./) {next}
									$sslcerts{$alias} = $sslcert;
									$sslkeys{$alias} = $sslkey;
								}
							}
						}
						$sslhost = "";
						$sslcert = "";
						$sslkey = "";
						$sslaliases = "";
					}
				}
			}
		}
		if (scalar(keys %sslcerts < 1)) {
			return (1, "No SSL certs found in MESSENGER_HTTPS_CONF location");
		}
		if (-e $config{MESSENGER_HTTPS_KEY}) {
			$sslkeys{''} = $config{MESSENGER_HTTPS_KEY};
		}
		if (-e $config{MESSENGER_HTTPS_CRT}) {
			$sslcerts{''} = $config{MESSENGER_HTTPS_CRT};
		}
		if ($config{DEBUG} >= 1) {
			foreach my $key (keys %sslcerts) {
				logfile("SSL: [$key] [$sslcerts{$key}] [$sslkeys{$key}]");
			}
		}
		eval {
			local $SIG{__DIE__} = undef;
			if ($config{MESSENGER6}) {
				$server = IO::Socket::SSL->new(
							Domain => AF_INET6,
							LocalPort => $port,
							Type => SOCK_STREAM,
							ReuseAddr => 1,
							Listen => $config{MESSENGER_CHILDREN},
							SSL_server => 1,
							SSL_use_cert => 1,
							SSL_cert_file => \%sslcerts,
							SSL_key_file => \%sslkeys,
				) or &error("MESSENGER: *Error* cannot open server on port $port: ".IO::Socket::SSL->errstr);
			} else {
				$server = IO::Socket::SSL->new(
							Domain => AF_INET,
							LocalPort => $port,
							Type => SOCK_STREAM,
							ReuseAddr => 1,
							Listen => $config{MESSENGER_CHILDREN},
							SSL_server => 1,
							SSL_use_cert => 1,
							SSL_cert_file => \%sslcerts,
							SSL_key_file => \%sslkeys,
				) or &error("MESSENGER: *Error* cannot open server on port $port: ".IO::Socket::SSL->errstr);
			}
			&logfile("Messenger HTTPS Service started for ".scalar(keys %sslcerts)." domains");
			$type = "HTML";
		};
		if ($@) {
			return (1, $@);
		}
	}
	elsif ($config{MESSENGER6}) {
		$server = IO::Socket::INET6->new(
			LocalPort => $port, 
			Type => SOCK_STREAM, 
			ReuseAddr => 1, 
			Listen => $config{MESSENGER_CHILDREN}) or &childcleanup(__LINE__,"*Error* cannot open server on port $port: $!");
	} else {
		$server = IO::Socket::INET->new(
			LocalPort => $port, 
			Type => SOCK_STREAM, 
			ReuseAddr => 1, 
			Listen => $config{MESSENGER_CHILDREN}) or &childcleanup(__LINE__,"*Error* cannot open server on port $port: $!");
	}
	
	my $index;
	if ($type eq "HTML" and $config{RECAPTCHA_SITEKEY} ne "") {$index = "/etc/csf/messenger/index.recaptcha.html"}
	elsif ($type eq "HTML") {$index = "/etc/csf/messenger/index.html"}
	else {$index = "/etc/csf/messenger/index.text"}
	open (my $IN, "<", $index);
	flock ($IN, LOCK_SH);
	my @message = <$IN>;
	close ($IN);
	chomp @message;

	my %images;
	if ($type eq "HTML") {
		opendir (DIR, "/etc/csf/messenger");
		foreach my $file (readdir(DIR)) {
			if ($file =~ /\.(gif|png|jpg)$/) {
				open (my $IN, "<", "/etc/csf/messenger/$file");
				flock ($IN, LOCK_SH);
				my @data = <$IN>;
				close ($IN);
				chomp @data;
				foreach my $line (@data) {
					$images{$file} .= "$line\n";
				}
			}
		}
		closedir (DIR);
	}
	my $chldallow = $config{MESSENGER_CHILDREN};

	if ($oldtype eq "HTTPS") {
		open (my $STATUS,"<", "/proc/$$/status") or next;
		flock ($STATUS, LOCK_SH);
		my @status = <$STATUS>;
		close ($STATUS);
		chomp @status;
		my $vmsize = 0;
		my $vmrss = 0;
		foreach my $line (@status) {
			if ($line =~ /^VmSize:\s+(\d+) kB$/) {$vmsize = $1}
			if ($line =~ /^VmRSS:\s+(\d+) kB$/) {$vmrss = $1}
		}

		logfile("lfd $oldtype messenger using $vmrss kB of RSS memory at startup, adding up to $config{MESSENGER_CHILDREN} children = ".(($config{MESSENGER_CHILDREN} + 1) * $vmrss)." kB");
		logfile("lfd $oldtype messenger using $vmsize kB of VIRT memory at startup, adding up to $config{MESSENGER_CHILDREN} children = ".(($config{MESSENGER_CHILDREN} + 1) * $vmsize)." kB");
	}

	if ($user ne "")
	{
		my (undef,undef,$uid,$gid,undef,undef,undef,$homedir) = getpwnam($user);
		if (($uid > 0) and ($gid > 0)) {
			my $dropfailure = &dropprivileges($uid, $gid);
			if (defined $dropfailure)
			{
				logfile("MESSENGER_USER unable to drop privileges ($dropfailure) - stopping $oldtype Messenger");
				exit;
			}

			my %children;
			while (1)
			{
				while (my $client = $server->accept())
				{
					while (scalar (keys %children) >= $chldallow)
					{
						sleep 1;
						foreach my $pid (keys %children) {
							unless (kill(0,$pid)) {delete $children{$pid}}
						}
						$0 = "lfd $oldtype messenger (busy)";
					}
	
					$0 = "lfd $oldtype messenger";
					$SIG{CHLD} = 'IGNORE';
					my $pid = fork;
					$children{$pid} = 1;
					if ($pid == 0)
					{
						eval
						{
							local $SIG{__DIE__} = undef;
							local $SIG{'ALRM'} = sub {die};
							alarm(10);
							close $server;

							$0 = "lfd $oldtype messenger client";

							binmode $client;
							$| = 1;
							my $firstline;

							my $hostaddress = $client->sockhost();
							my $peeraddress = $client->peerhost();
							$peeraddress =~ s/^::ffff://;
							$hostaddress =~ s/^::ffff://;

							if ($type eq "HTML")
							{
								while ($firstline !~ /\n$/)
								{
									my $char;
									$client->read($char,1);
									$firstline .= $char;
									if ($char eq "") {exit}

									# #
									#	RFC 7230, Sec 3.1.1: recommends supporting at least 8000 octets.
									#		Prefix: 	GET /unblk?g-recaptcha-response=	= 32 bytes
									#		Suffix:  	HTTP/1.1\r\n						= 11 bytes			(\r\n = 2 bytes) (carriage return (0x0D)/line feed (0x0A))
									#		 												32 + 11 = 43 bytes
									#	
									#		Remaining for Recaptcha token					4053 bytes
									#		Acceptable Limit								4096 bytes
									#	
									#	@since				v15.10
									#	@reference			https://datatracker.ietf.org/doc/html/rfc7230#autoid-17
									#						https://mothereff.in/byte-counter
									# #

									if ( length $firstline > 4096 )
									{
										last
									}
								}

								chomp $firstline;
								if ($firstline =~ /\r$/) {chop $firstline}
							}

							&messengerlog($homedir,"Client connection [$peeraddress] [$firstline]");
							my $error;
							my $success;
							my $failure;
							if (($type eq "HTML") and ($firstline =~ /^GET \/unblk\?g-recaptcha-response=(\S+)/i)) {
								my $recv = $1;
								my $status = 1;
								my $text;
								
								# $recv is an unauthenticated, network-supplied reCAPTCHA response
								# token that is interpolated into the siteverify URL below. Reject
								# anything outside the reCAPTCHA token grammar so a hostile value
								# cannot alter the request, even when URLGet falls back to
								# curl/wget. Defence in depth alongside the list-form open3 fix in
								# ConfigServer::URLGet.
								if ($recv !~ /\A[A-Za-z0-9_-]+\z/) {
									$text = "rejected malformed reCAPTCHA response token";
								} else {
									eval {
										local $SIG{__DIE__} = undef;
										eval("no lib '/usr/local/csf/lib'");
										my $urlget = ConfigServer::URLGet->new(2, "", $config{URLPROXY});
										my $url = "https://www.google.com/recaptcha/api/siteverify?secret=$config{RECAPTCHA_SECRET}&response=$recv";
										($status, $text) = $urlget->urlget($url);
									};
								}
								if ($status) {
									&messengerlog($homedir,"*Error*, ReCaptcha ($peeraddress): $text");
									if ($config{DEBUG} >= 1) {
										if ($@) {$error .= "Error:".$@}
										if ($!) {$error .= "Error:".$!}
										$error .= " Error Status: $status";
									}
									$error .= "Unable to verify with Google reCAPTCHA";
								} else {
									my $resp  = JSON::Tiny::decode_json($text);
									if ($resp->{success}) {
										my $ip = $resp->{hostname};
										unless ($ip =~ /^($ipv4reg|$ipv6reg)$/) {$ip = (getips($ip))[0]}
										if ($ips{$ip} or $ip eq $hostaddress or $ipscidr6->find($ip)) {
											sysopen (my $UNBLOCK, "$homedir/unblock.txt", O_WRONLY | O_APPEND | O_CREAT) or $error .= "Unable to write to [$homedir/unblock.txt] (make sure that MESSENGER_USER has a home directory)";
											flock($UNBLOCK, LOCK_EX);
											print $UNBLOCK "$peeraddress;$resp->{hostname};$ip\n";
											close ($UNBLOCK);
											$success = 1;
											&messengerlog($homedir,"*Success*, ReCaptcha ($peeraddress): [$resp->{hostname} ($ip)] requested unblock");
										} else {
											$error .= "Failed, [$resp->{hostname} ($ip)] does not appear to be hosted on this server.";
											&messengerlog($homedir,"*Failed*, ReCaptcha ($peeraddress): [$resp->{hostname} ($ip)] does not appear to be hosted on this server");
										}
									} else {
										$failure = 1;
										my @codes = @{$resp->{'error-codes'}};
										&messengerlog($homedir,"*Failure*, ReCaptcha ($peeraddress): [$codes[0]]");
									}
								}
							}
							if (($type eq "HTML") and ($firstline =~ /^GET\s+(\S*\/)?(\S*\.(gif|png|jpg))\s+/i)) {
								my $type = $3;
								if ($type eq "jpg") {$type = "jpeg"}
								print $client "HTTP/1.1 200 OK\r\n";
								print $client "Content-type: image/$type\r\n";
								print $client "\r\n";
								print $client $images{$2};
							} else {
								if ($type eq "HTML") {
									print $client "HTTP/1.1 403 OK\r\n";
									print $client "Content-type: text/html\r\n";
									print $client "\r\n";
									foreach my $line (@message) {
										if ($line =~ /\[IPADDRESS\]/) {$line =~ s/\[IPADDRESS\]/$peeraddress/}
										if ($line =~ /\[HOSTNAME\]/) {$line =~ s/\[HOSTNAME\]/$hostname/}
										if ($line =~ /\[RECAPTCHA_SITEKEY\]/) {$line =~ s/\[RECAPTCHA_SITEKEY\]/$config{RECAPTCHA_SITEKEY}/}
										if ($line =~ /\[RECAPTCHA_ERROR=\"([^\"]+)\"\]/) {
											my $text = $1;
											if ($error ne "") {$line =~ s/\[RECAPTCHA_ERROR=\"([^\"]+)\"\]/$text $error/} else {$line =~ s/\[RECAPTCHA_ERROR=\"([^\"]+)\"\]//}
										}
										if ($line =~ /\[RECAPTCHA_SUCCESS=\"([^\"]+)\"\]/) {
											my $text = $1;
											if ($success) {$line =~ s/\[RECAPTCHA_SUCCESS=\"([^\"]+)\"\]/$text/} else {$line =~ s/\[RECAPTCHA_SUCCESS=\"([^\"]+)\"\]//}
										}
										if ($line =~ /\[RECAPTCHA_FAILURE=\"([^\"]+)\"\]/) {
											my $text = $1;
											if ($failure) {$line =~ s/\[RECAPTCHA_FAILURE=\"([^\"]+)\"\]/$text/} else {$line =~ s/\[RECAPTCHA_FAILURE=\"([^\"]+)\"\]//}
										}
										print $client "$line\r\n";
									}
									print $client "\r\n";
								} else {
									foreach my $line (@message) {
										if ($line =~ /\[IPADDRESS\]/) {$line =~ s/\[IPADDRESS\]/$peeraddress/}
										if ($line =~ /\[HOSTNAME\]/) {$line =~ s/\[HOSTNAME\]/$hostname/}
										print $client "$line ";
									}
									print $client "\n";
								}
							}
							alarm(0);
						};
						shutdown ($client,2);
						$client->close();
						alarm(0);
						exit;
					}
					if ($oldtype eq "HTTPS") {
						$client->close(SSL_no_shutdown => 1);
					} else {
						$client->close();
					}
				}
			}
		} else {
			logfile("MESSENGER_USER invalid - stopping $oldtype Messenger");
		}
	} else {
		logfile("MESSENGER_USER not set - stopping $oldtype Messenger");
	}
	return;
}
# end messenger
###############################################################################
# start messengerv2
sub messengerv2 {
	my (undef,undef,$uid,$gid,undef,undef,undef,$homedir) = getpwnam($config{MESSENGER_USER});

	# MESSENGER_USER must be a real, unprivileged account. Without this check
	# a misconfigured MESSENGER_USER leaves the network-facing messenger
	# running as root, so any flaw in it becomes a full compromise. The v1
	# messenger already refuses uid/gid 0; v2 and v3 did not.
	if (!defined $uid or !defined $gid or $uid == 0 or $gid == 0) {
		return (1, "MESSENGER_USER [$config{MESSENGER_USER}] must be an existing non-root user");
	}
	if ($homedir eq "" or $homedir eq "/" or $homedir =~ m[/etc/csf]) {
		return (1, "The home directory for $config{MESSENGER_USER} is not valid [$homedir]");
	}
	if (! -e $homedir) {
		return (1, "The home directory for $config{MESSENGER_USER} does not exist [$homedir]");
	}
	system("chmod","711",$homedir);
	my $public_html = $homedir."/public_html";
	# "nobody" is a name, and a name is whatever /etc/group says it is. On a
	# host where it has been pointed at gid 0, this chown would hand the
	# document root to the root group. MESSENGERV3 settles the same question
	# from MESSENGERV3GROUP at the same point.
	my $public_gid = &resolvegroup("nobody");
	if (!defined $public_gid) {
		return (2, "The nobody group does not exist");
	}
	if ($public_gid == 0) {
		return (2, "The nobody group must not resolve to the root group (gid 0)");
	}
	unless (-e $public_html) {
		system("mkdir","-p",$public_html);
		system("chown","$config{MESSENGER_USER}:nobody",$public_html);
		system("chmod","711",$public_html);
	}
	unless (-e $public_html."/.htaccess") {
		open (my $HTACCESS, ">", $public_html."/.htaccess");
		flock ($HTACCESS, LOCK_EX);
		print $HTACCESS "Require all granted\n";
		print $HTACCESS "DirectoryIndex index.php index.cgi index.html index.htm\n";
		# No "Options +FollowSymLinks +ExecCGI": the unblock page is static
		# plus one PHP script and needs neither, while this directory is
		# writable by MESSENGER_USER. messengervhostsec() now sets
		# AllowOverride None, so this file is inert in any case; the line is
		# gone rather than merely overridden so that a host which grants
		# overrides elsewhere does not pick it back up. MESSENGERV3 has
		# carried it commented out for the same reason.
		print $HTACCESS "RewriteEngine On\n";
		print $HTACCESS "RewriteCond \%{REQUEST_FILENAME} !-f\n";
		print $HTACCESS "RewriteCond \%{REQUEST_FILENAME} !-d\n";
		print $HTACCESS "RewriteRule ^ /index.php [L,QSA]\n";
		system("chown","$config{MESSENGER_USER}:$config{MESSENGER_USER}",$public_html."/.htaccess");
		system("chmod","644",$public_html."/.htaccess");
	}
	unless (-e $public_html."/index.php") {
		if ($config{RECAPTCHA_SITEKEY}) {
			system("cp","/etc/csf/messenger/index.recaptcha.php",$public_html."/index.php");
		} else {
			system("cp","/etc/csf/messenger/index.php",$public_html."/index.php");
		}
		system("chown","$config{MESSENGER_USER}:$config{MESSENGER_USER}",$public_html."/index.php");
		system("chmod","644",$public_html."/index.php");
	}
	unless (-e $homedir."/en.php") {
		system("cp","/etc/csf/messenger/en.php",$homedir."/en.php");
		system("chown","$config{MESSENGER_USER}:$config{MESSENGER_USER}",$homedir."/en.php");
		system("chmod","644",$homedir."/en.php");
	}
	open (my $CONF, ">", $homedir."/recaptcha.php");
	flock ($CONF, LOCK_EX);
	print $CONF "<?php\n";
	print $CONF "\$secret = '$config{RECAPTCHA_SECRET}';\n";
	print $CONF "\$sitekey = '$config{RECAPTCHA_SITEKEY}';\n";
	print $CONF "\$unblockfile = '$homedir/unblock.txt';\n";
	print $CONF "\$logfile = '/var/log/lfd_messenger.log';\n";
	print $CONF "?>\n";
	system("chown","$config{MESSENGER_USER}:$config{MESSENGER_USER}",$homedir."/recaptcha.php");
	system("chmod","600",$homedir."/recaptcha.php");

	
	open (my $OUT, ">", "/var/lib/csf/csf.conf");
	flock ($OUT, LOCK_EX);

	if ($config{MESSENGER_HTML_IN} ne "") {
		print $OUT "Listen 0.0.0.0:$config{MESSENGER_HTML}\n";
		if ($config{IPV6}) {print $OUT "Listen [::]:$config{MESSENGER_HTML}\n"}
		print $OUT "<VirtualHost *:$config{MESSENGER_HTML}>\n";
		print $OUT " ServerName $hostname\n";
		print $OUT " DocumentRoot $public_html\n";
		print $OUT messengervhostsec($homedir, $public_html);
		print $OUT " <IfModule suphp_module>\n";
		print $OUT "   suPHP_UserGroup $config{MESSENGER_USER} $config{MESSENGER_USER}\n";
		print $OUT " </IfModule>\n";
		print $OUT " <IfModule suexec_module>\n";
		print $OUT "   <IfModule !mod_ruid2.c>\n";
		print $OUT "     SuexecUserGroup $config{MESSENGER_USER} $config{MESSENGER_USER}\n";
		print $OUT "   </IfModule>\n";
		print $OUT " </IfModule>\n";
		print $OUT " <IfModule ruid2_module>\n";
		print $OUT "   RMode config\n";
		print $OUT "   RUidGid $config{MESSENGER_USER} $config{MESSENGER_USER}\n";
		print $OUT " </IfModule>\n";
		print $OUT " <IfModule mpm_itk.c>\n";
		print $OUT "   AssignUserID $config{MESSENGER_USER} $config{MESSENGER_USER}\n";
		print $OUT " </IfModule>\n";
		print $OUT " KeepAlive Off\n";
		print $OUT "</VirtualHost>\n";
	}

	if ($config{MESSENGER_HTTPS_IN} ne "") {
		my %sslcerts;
		my %sslkeys;
		my %ssldomains;
		my $start = 0;
		my $sslhost;
		my $sslcert;
		my $sslkey;
		my $sslaliases;
		my $ssldir = "/var/lib/csf/ssl/";
		unless (-d $ssldir) {
			mkdir $ssldir;
			mkdir $ssldir."certs/";
			mkdir $ssldir."keys/";
		}
		foreach my $file (glob($config{MESSENGER_HTTPS_CONF})) {
			if (-e $file) {
				foreach my $line (slurp($file)) {
					$line =~ s/\'|\"//g;
					if ($line =~ /^\s*<VirtualHost\s+[^\>]+>/) {
						$start = 1;
					}
					if ($webserver eq "apache" and $start) {
						if ($line =~ /\s*ServerName\s+(\w+:\/\/)?([a-zA-Z0-9\.\-]+)(:\d+)?/) {$sslhost = $2}
						if ($line =~ /\s*ServerAlias\s+(.*)/) {$sslaliases .= " ".$1}
						if ($line =~ /\s*SSLCertificateFile\s+(\S+)/) {
							my $match = $1;
							if (-e $match) {
								copy($match, $ssldir."certs/".$sslhost."\.crt");
								$sslcert = $ssldir."certs/".$sslhost."\.crt";
							}
						}
						if ($line =~ /\s*SSLCertificateKeyFile\s+(\S+)/) {
							my $match = $1;
							if (-e $match) {
								copy($match, $ssldir."keys/".$sslhost."\.key");
								$sslkey = $ssldir."keys/".$sslhost."\.key";
							}
						}
					}
					
					if (($webserver eq "apache" and $line =~ /^\s*<\/VirtualHost\s*>/)) {
						$start = 0;
						if ($sslhost ne "" and !checkip($sslhost) and $sslcert ne "") {
							$ssldomains{$sslhost}{key} = $sslkey;
							$ssldomains{$sslhost}{aliases} = $sslaliases;
							$ssldomains{$sslhost}{cert} = $sslcert;
						}
						$sslhost = "";
						$sslcert = "";
						$sslkey = "";
						$sslaliases = "";
					}
				}
			}
		}
		if (scalar(keys %ssldomains < 1)) {
			return (1, "No SSL domains found in MESSENGER_HTTPS_CONF location");
		}

		print $OUT "Listen 0.0.0.0:$config{MESSENGER_HTTPS}\n";
		if ($config{IPV6}) {print $OUT "Listen [::]:$config{MESSENGER_HTTPS}\n"}
		if (-e $config{MESSENGER_HTTPS_KEY}) {
			print $OUT "<VirtualHost *:$config{MESSENGER_HTTPS}>\n";
			print $OUT " ServerName $hostname\n";
			print $OUT " DocumentRoot $public_html\n";
			print $OUT " UseCanonicalName Off\n";
			print $OUT messengervhostsec($homedir, $public_html);
			print $OUT " <IfModule suphp_module>\n";
			print $OUT "   suPHP_UserGroup $config{MESSENGER_USER} $config{MESSENGER_USER}\n";
			print $OUT " </IfModule>\n";
			print $OUT " <IfModule suexec_module>\n";
			print $OUT "   <IfModule !mod_ruid2.c>\n";
			print $OUT "     SuexecUserGroup $config{MESSENGER_USER} $config{MESSENGER_USER}\n";
			print $OUT "   </IfModule>\n";
			print $OUT " </IfModule>\n";
			print $OUT " <IfModule ruid2_module>\n";
			print $OUT "   RMode config\n";
			print $OUT "   RUidGid $config{MESSENGER_USER} $config{MESSENGER_USER}\n";
			print $OUT " </IfModule>\n";
			print $OUT " <IfModule mpm_itk.c>\n";
			print $OUT "   AssignUserID $config{MESSENGER_USER} $config{MESSENGER_USER}\n";
			print $OUT " </IfModule>\n";
			print $OUT " SSLEngine on\n";
			if (-e $config{MESSENGER_HTTPS_KEY}) {
				copy($config{MESSENGER_HTTPS_KEY}, $ssldir."keys/".$hostname."\.key");
				print $OUT " SSLCertificateKeyFile ".$ssldir."keys/".$hostname."\.key\n";
			}
			if (-e $config{MESSENGER_HTTPS_CRT}) {
				copy($config{MESSENGER_HTTPS_CRT}, $ssldir."certs/".$hostname."\.crt");
				print $OUT " SSLCertificateFile ".$ssldir."certs/".$hostname."\.crt\n";
			}
			print $OUT " SSLUseStapling off\n";
			print $OUT " KeepAlive Off\n";
			print $OUT "</VirtualHost>\n";
		}
		foreach my $key (keys %ssldomains) {
			if ($key eq "") {next}
			if ($key =~ /^\s+$/) {next}
			if (-e $ssldomains{$key}{cert}) {
				print $OUT "<VirtualHost *:$config{MESSENGER_HTTPS}>\n";
				print $OUT " ServerName $key\n";
				print $OUT " ServerAlias $ssldomains{$key}{aliases}\n";
				print $OUT " DocumentRoot $public_html\n";
				print $OUT " UseCanonicalName Off\n";
				print $OUT messengervhostsec($homedir, $public_html);
				print $OUT " <IfModule suphp_module>\n";
				print $OUT "   suPHP_UserGroup $config{MESSENGER_USER} $config{MESSENGER_USER}\n";
				print $OUT " </IfModule>\n";
				print $OUT " <IfModule suexec_module>\n";
				print $OUT "   <IfModule !mod_ruid2.c>\n";
				print $OUT "     SuexecUserGroup $config{MESSENGER_USER} $config{MESSENGER_USER}\n";
				print $OUT "   </IfModule>\n";
				print $OUT " </IfModule>\n";
				print $OUT " <IfModule ruid2_module>\n";
				print $OUT "   RMode config\n";
				print $OUT "   RUidGid $config{MESSENGER_USER} $config{MESSENGER_USER}\n";
				print $OUT " </IfModule>\n";
				print $OUT " <IfModule mpm_itk.c>\n";
				print $OUT "   AssignUserID $config{MESSENGER_USER} $config{MESSENGER_USER}\n";
				print $OUT " </IfModule>\n";
				print $OUT " SSLEngine on\n";
				if (-e $ssldomains{$key}{cert}) {print $OUT " SSLCertificateFile $ssldomains{$key}{cert}\n"}
				if (-e $ssldomains{$key}{key}) {print $OUT " SSLCertificateKeyFile $ssldomains{$key}{key}\n"}
				print $OUT " SSLUseStapling off\n";
				print $OUT " KeepAlive Off\n";
				print $OUT "</VirtualHost>\n";
			}
		}
	}
	close ($OUT);

	system("cp","-f","/var/lib/csf/csf.conf","/etc/apache2/conf.d/csf.messenger.conf");

	my ($childin, $childout);
	my $cmdpid = open3($childin, $childout, $childout, "/usr/sbin/apachectl", "configtest");
	my @data = <$childout>;
	waitpid ($cmdpid, 0);

	if (-e "/var/lib/csf/apachectl.error") {unlink("/var/lib/csf/apachectl.error")}
	my $ok = 0;
	foreach (@data) {
		if ($_ =~ /^Syntax OK/) {$ok = 1}
	}
	if ($ok) {
		system("/scripts/restartsrv_httpd");
		logfile("MESSENGERV2: Started Apache MESSENGERV2 service using /etc/apache2/conf.d/csf.messenger.conf");
	} else {
		logfile("*MESSENGERV2*: Unable to generate a valid Apache configuration, see /var/lib/csf/apachectl.error");
		if (-e "/etc/apache2/conf.d/csf.messenger.conf") {unlink("/etc/apache2/conf.d/csf.messenger.conf")}
		system("/scripts/restartsrv_httpd");
		
		open (my $ERROR, ">", "/var/lib/csf/apachectl.error");
		flock ($ERROR, LOCK_EX);
		foreach (@data) {print $ERROR $_}
		close ($ERROR);
	}
	return;
}
# end messengerv2
###############################################################################
# start messengerv3
sub messengerv3 {
	my (undef,undef,$uid,$gid,undef,undef,undef,$homedir) = getpwnam($config{MESSENGER_USER});

	# MESSENGER_USER must be a real, unprivileged account. Without this check
	# a misconfigured MESSENGER_USER leaves the network-facing messenger
	# running as root, so any flaw in it becomes a full compromise. The v1
	# messenger already refuses uid/gid 0; v2 and v3 did not.
	if (!defined $uid or !defined $gid or $uid == 0 or $gid == 0) {
		return (1, "MESSENGER_USER [$config{MESSENGER_USER}] must be an existing non-root user");
	}
	if ($homedir eq "" or $homedir eq "/" or $homedir =~ m[/etc/csf]) {
		return (1, "The home directory for $config{MESSENGER_USER} is not valid [$homedir]");
	}
	if (! -e $homedir) {
		return (1, "The home directory for $config{MESSENGER_USER} does not exist [$homedir]");
	}
	my $public_html = $homedir."/public_html";
	my $public_gid = &resolvegroup($config{MESSENGERV3GROUP});
	if (!defined $public_gid) {
		return (3, "MESSENGERV3GROUP [".($config{MESSENGERV3GROUP} // "")."] is not a valid group name or gid");
	}
	if ($public_gid == 0) {
		return (3, "MESSENGERV3GROUP [".($config{MESSENGERV3GROUP} // "")."] must not resolve to the root group (gid 0)");
	}
	unless (-e $public_html) {
		system("mkdir","-p",$public_html);
		system("chown","$config{MESSENGER_USER}:$config{MESSENGERV3GROUP}",$public_html);
		system("chmod",$config{MESSENGERV3PERMS},$public_html);
	}
	unless (-e $public_html."/.htaccess") {
		open (my $HTACCESS, ">", $public_html."/.htaccess");
		flock ($HTACCESS, LOCK_EX);
		print $HTACCESS <<EOF;
Require all granted
DirectoryIndex index.php index.cgi index.html index.htm
#Options +FollowSymLinks +ExecCGI
RewriteEngine On
RewriteCond \%{REQUEST_FILENAME} !-f
RewriteCond \%{REQUEST_FILENAME} !-d
RewriteRule ^ /index.php [L,QSA]
EOF
		system("chown","$config{MESSENGER_USER}:$config{MESSENGER_USER}",$public_html."/.htaccess");
		system("chmod","644",$public_html."/.htaccess");
	}
	unless (-e $public_html."/index.php") {
		if ($config{RECAPTCHA_SITEKEY}) {
			system("cp","/etc/csf/messenger/index.recaptcha.php",$public_html."/index.php");
		} else {
			system("cp","/etc/csf/messenger/index.php",$public_html."/index.php");
		}
		system("chown","$config{MESSENGER_USER}:$config{MESSENGER_USER}",$public_html."/index.php");
		system("chmod","644",$public_html."/index.php");
	}
	unless (-e $homedir."/en.php") {
		system("cp","/etc/csf/messenger/en.php",$homedir."/en.php");
		system("chown","$config{MESSENGER_USER}:$config{MESSENGER_USER}",$homedir."/en.php");
		system("chmod","644",$homedir."/en.php");
	}
	open (my $CONF, ">", $homedir."/recaptcha.php");
	flock ($CONF, LOCK_EX);
	print $CONF "<?php\n";
	print $CONF "\$secret = '$config{RECAPTCHA_SECRET}';\n";
	print $CONF "\$sitekey = '$config{RECAPTCHA_SITEKEY}';\n";
	print $CONF "\$unblockfile = '$homedir/unblock.txt';\n";
	print $CONF "\$logfile = '/var/log/lfd_messenger.log';\n";
	print $CONF "?>\n";
	system("chown","$config{MESSENGER_USER}:$config{MESSENGER_USER}",$homedir."/recaptcha.php");
	system("chmod","600",$homedir."/recaptcha.php");

	if ($config{MESSENGERV3WEBSERVER} eq "apache") {
		$webserver = "apache";
	}
	elsif ($config{MESSENGERV3WEBSERVER} eq "litespeed") {
		$webserver = "litespeed";
	}

	open (my $OUT, ">", "/var/lib/csf/csf.conf");
	flock ($OUT, LOCK_EX);

	if ($config{MESSENGERV3PHPHANDLER} ne "") {
		$phphandler = $config{MESSENGERV3PHPHANDLER};
	} else {
		my $file = "/etc/httpd/conf/extra/httpd-hostname.conf";
		if (-e $file) {
			foreach my $line (slurp($file)) {
				if ($line =~ /^\s*AddHandler\s+.+\s+\.php/) {
					$phphandler = $line;
					if ($config{DEBUG} >= 1) {logfile("SSL: PHP Handler found in [$file]")}
				}
			}
		}
	}

	foreach my $line (slurp("/usr/local/csf/tpl/$webserver.main.txt")) {
		$line =~ s/\[PORT\]/$config{MESSENGER_HTML}/g;
		if ($line =~ /Listen \[::\]:/ and !$config{IPV6}) {next}
		$line =~ s/\[SERVERNAME\]/$hostname/g;
		$line =~ s/\[DOCUMENTROOT\]/$public_html/g;
		$line =~ s/\[DIRECTORY\]/$homedir/g;
		$line =~ s/\[USER\]/$config{MESSENGER_USER}/g;
		$line =~ s/\[PHPHANDLER\]/$phphandler/g;
		print $OUT $line."\n";
	}
	
	if ($config{MESSENGER_HTML_IN} ne "") {
		foreach my $line (slurp("/usr/local/csf/tpl/$webserver.http.txt")) {
			$line =~ s/\[PORT\]/$config{MESSENGER_HTML}/g;
			if ($line =~ /Listen \[::\]:/ and !$config{IPV6}) {next}
			$line =~ s/\[SERVERNAME\]/$hostname/g;
			$line =~ s/\[DOCUMENTROOT\]/$public_html/g;
			$line =~ s/\[DIRECTORY\]/$homedir/g;
			$line =~ s/\[USER\]/$config{MESSENGER_USER}/g;
			$line =~ s/\[PHPHANDLER\]/$phphandler/g;
			print $OUT $line."\n";
		}
	}

	if ($config{MESSENGER_HTTPS_IN} ne "") {
		if ($webserver eq "litespeed") {
			if ($config{MESSENGERV3HTTPS_CONF} =~ /(.*\/lsws\/)/) {
				$serverroot = $1;
			}
		}
		&conftree($config{MESSENGERV3HTTPS_CONF});
		if ($webserver eq "litespeed") {
			if ($sslhost ne "" and $osslcert ne "" and $ssldomains{$sslhost}{cert} eq "") {
				if (-e $osslcert) {
					$sslcert = $ssldir."certs/".$sslhost."\.crt";
					copy($osslcert, $ssldir."certs/".$sslhost."\.crt");
				}
				if (-e $osslkey) {
					$sslkey = $ssldir."keys/".$sslhost."\.key";
					copy($osslkey, $ssldir."keys/".$sslhost."\.key");
				}
				if (-e $osslca) {
					$sslca = $ssldir."ca/".$sslhost."\.ca";
					copy($osslca, $ssldir."ca/".$sslhost."\.ca");
				}
				$sslaliases =~ s/\$VH_NAME/$sslhost/;
				$ssldomains{$sslhost}{key} = $sslkey;
				$ssldomains{$sslhost}{aliases} = $sslaliases;
				$ssldomains{$sslhost}{cert} = $sslcert;
				$ssldomains{$sslhost}{ca} = $sslca;
				push @ssldomainkeys, $sslhost;

				$sslhost = "";
				$sslcert = "";
				$sslkey = "";
				$sslca = "";
				$osslcert = "";
				$osslkey = "";
				$osslca = "";
				$sslaliases = "";
			}
		}

		if (scalar(keys %ssldomains < 1)) {
			return (1, "No SSL domains found in MESSENGERV3HTTPS_CONF location [$config{MESSENGERV3HTTPS_CONF}] for $webserver web server");
		}

		my @virtualhost;
		my $start = 0;
		my $key = $ssldomainkeys[0];
		foreach my $line (slurp("/usr/local/csf/tpl/$webserver.https.txt")) {
			if ($line =~ /^\# Virtualhost start/) {$start = 1}
			if ($start) {
				if ($line =~ /^\# Virtualhost end/) {$start = 0}
				push @virtualhost, $line;
				next;
			}
			$line =~ s/\[SSLPORT\]/$config{MESSENGER_HTTPS}/g;
			if ($line =~ /Listen \[::\]:/ and !$config{IPV6}) {next}
			$line =~ s/\[SERVERNAME\]/$hostname/g;
			$line =~ s/\[DOCUMENTROOT\]/$public_html/g;
			$line =~ s/\[DIRECTORY\]/$homedir/g;
			$line =~ s/\[USER\]/$config{MESSENGER_USER}/g;
			$line =~ s/\[PHPHANDLER\]/$phphandler/g;
			if ($line =~ /[MAPS]/) {
				my $mapping;
				foreach my $map (@ssldomainkeys) {
					if (-e $ssldomains{$map}{cert}) {
						$mapping .= "map csfssl.${map} ${map}\n\t";
					}
				}
				$line =~ s/\[MAPS\]/$mapping/g;
			}
			if ($line =~ /\[SSLCERTIFICATEFILE\]/) {
				if ( -e $ssldomains{$key}{cert}) {
					$line =~ s/\[SSLCERTIFICATEFILE\]/$ssldomains{$key}{cert}/g;
				} else {next}
			}

			if ($line =~ /\[SSLCERTIFICATEKEYFILE\]/) {
				if (-e $ssldomains{$key}{key}) {
					$line =~ s/\[SSLCERTIFICATEKEYFILE\]/$ssldomains{$key}{key}/g;
				} else {next}
			}

			if ($line =~ /\[SSLCACERTIFICATEFILE\]/) {
				if (-e $ssldomains{$key}{ca}) {
					$line =~ s/\[SSLCACERTIFICATEFILE\]/$ssldomains{$key}{ca}/g;
				} else {next}
			}

			print $OUT $line."\n";
		}

		foreach my $key (@ssldomainkeys) {
			if ($key eq "") {next}
			if ($key =~ /^\s+$/) {next}
			if ($config{DEBUG} >= 1) {logfile("SSL: Processing [$key]")}

			if (-e $ssldomains{$key}{cert}) {
				foreach (@virtualhost) {
					my $line = $_;
					$line =~ s/\[SSLPORT\]/$config{MESSENGER_HTTPS}/g;
					$line =~ s/\[SERVERNAME\]/$key/g;
					$line =~ s/\[SERVERALIAS\]/$ssldomains{$key}{aliases}/g;
					$line =~ s/\[DOCUMENTROOT\]/$public_html/g;
					$line =~ s/\[DIRECTORY\]/$homedir/g;
					$line =~ s/\[USER\]/$config{MESSENGER_USER}/g;
					$line =~ s/\[PHPHANDLER\]/$phphandler/g;

					if ($line =~ /\[SSLCERTIFICATEFILE\]/) {
						if ( -e $ssldomains{$key}{cert}) {
							$line =~ s/\[SSLCERTIFICATEFILE\]/$ssldomains{$key}{cert}/g;
						} else {next}
					}

					if ($line =~ /\[SSLCERTIFICATEKEYFILE\]/) {
						if (-e $ssldomains{$key}{key}) {
							$line =~ s/\[SSLCERTIFICATEKEYFILE\]/$ssldomains{$key}{key}/g;
						} else {next}
					}

					if ($line =~ /\[SSLCACERTIFICATEFILE\]/) {
						if (-e $ssldomains{$key}{ca}) {
							$line =~ s/\[SSLCACERTIFICATEFILE\]/$ssldomains{$key}{ca}/g;
						} else {next}
					}

					print $OUT $line."\n";
				}
			}
		}
	}
	close ($OUT);

	my $location;
	if (-d $config{MESSENGERV3LOCATION}) {
		system("cp","-f","/var/lib/csf/csf.conf",$config{MESSENGERV3LOCATION}."/csf.messenger.conf");
		$location = $config{MESSENGERV3LOCATION}."/csf.messenger.conf";
	}
	elsif (-f $config{MESSENGERV3LOCATION}) {
		my @conf = slurp($config{MESSENGERV3LOCATION});
		unless (grep {$_ =~ m[^Include /var/lib/csf/csf.conf]i} @conf) {
			sysopen (my $FILE, $config{MESSENGERV3LOCATION}, O_WRONLY | O_APPEND | O_CREAT);
			flock ($FILE, LOCK_EX);
			if ($webserver eq "apache") {
				print $FILE "Include /var/lib/csf/csf.conf\n";
			}
			elsif ($webserver eq "litespeed") {
				print $FILE "include /var/lib/csf/csf.conf\n";
			}
			close ($FILE);
		}
		$location = $config{MESSENGERV3LOCATION};
	}
	else {
		logfile("MESSENGERV3: [$config{MESSENGERV3LOCATION}] is neither a directory nor a file. You must manually include /var/lib/csf/csf.conf into the $webserver configuration");
		return;
	}

	if ($config{MESSENGERV3TEST} ne "") {
		my ($childin, $childout);
		my $cmdpid = open3($childin, $childout, $childout, $config{MESSENGERV3TEST});
		my @data = <$childout>;
		waitpid ($cmdpid, 0);

		if (-e "/var/lib/csf/messenger.error") {unlink("/var/lib/csf/messenger.error")}
		my $ok = 0;
		foreach (@data) {
			if ($_ =~ /^Syntax OK/) {$ok = 1}
		}
		if ($ok) {
			system($config{MESSENGERV3RESTART});
			logfile("MESSENGERV3: Restarted $webserver MESSENGERV3 service using $location");
		} else {
			open (my $ERROR, ">", "/var/lib/csf/messenger.error");
			flock ($ERROR, LOCK_EX);
			foreach (@data) {print $ERROR $_}
			close ($ERROR);

			if (-d $config{MESSENGERV3LOCATION}) {
				unlink ($config{MESSENGERV3LOCATION}."/csf.messenger.conf");
			}
			elsif (-f $config{MESSENGERV3LOCATION}) {
				my @conf = slurp($config{MESSENGERV3LOCATION});
				if (grep {$_ =~ m[^Include /var/lib/csf/csf.conf]i} @conf) {
					sysopen (my $FILE, $config{MESSENGERV3LOCATION}, O_WRONLY | O_CREAT | O_TRUNC);
					flock ($FILE, LOCK_EX);
					foreach my $line (@conf) {
						$line =~ s/$cleanreg//g;
						if ($line =~ m[^Include /var/lib/csf/csf.conf]i) {next}
						print $FILE $line."\n";
					}
					close ($FILE);
				}
			}

			system($config{MESSENGERV3RESTART});

			logfile("*MESSENGERV3*: Unable to generate a valid $webserver configuration, see /var/lib/csf/messenger.error");
		}
	} else {
		system($config{MESSENGERV3RESTART});
		logfile("MESSENGERV3: Restarted $webserver MESSENGERV3 service using $location");
	}
	return;
}
# end messengerv3
###############################################################################
# start messengerlog
###############################################################################
# start resolvegroup
#
# Resolve a configured group to a gid, so the messenger can refuse a document
# root owned by the root group before it creates one. Returns undef when the
# value names no group.
#
# Accepts a name or a bare numeric gid, because both forms work in the chown
# that follows and both therefore have to be checked. A literal is not the only
# way gid 0 arrives: getgrnam() reads /etc/group, so a host that has pointed
# "nobody" at gid 0 reaches the same place through a name that looks harmless.
#
# A numeric value is bounded before it is believed. Outside the range a gid can
# hold, the kernel truncates on the way in and the value that lands is not the
# value that was checked -- 4294967296 arrives as 0.
sub resolvegroup {
	my $group = shift;

	return undef if (!defined $group);
	$group =~ s/^\s+|\s+$//g;
	return undef if ($group eq "");

	if ($group =~ /^\d+$/) {
		return undef if ($group > 0xFFFFFFFE);
		return $group + 0;
	}

	my $gid = getgrnam($group);

	return defined $gid ? $gid + 0 : undef;
}
# end resolvegroup
###############################################################################
# start dropprivileges
#
# Permanently drop the v1 messenger to MESSENGER_USER before it serves
# anything. Returns undef once the drop has been verified, and otherwise a
# short reason for the caller to log before it stops the messenger.
#
# Assigning to $< / $> / $( / $) changes only the real and effective ids: the
# saved set-user-ID and set-group-ID stay at 0, so a single "$> = 0" anywhere
# in the request handler restores full root (CWE-273). The previous code did
# exactly that, and did it through "local", which by construction means the
# drop was reversible -- Perl restores those values on scope exit, which it
# could only do because the saved ids were still privileged. The handler this
# protects parses an attacker-supplied HTTP request line and a reCAPTCHA
# response fetched from the network, so the drop has to be irreversible.
#
# setgid(2) and setuid(2) set the real, effective and saved id together when
# called with an effective uid of 0, which is what makes it permanent. Order
# matters and cannot be rearranged: the supplementary groups have to go first
# because setgroups(2) needs privilege, and the uid has to go last because
# after it drops there is no privilege left to change the gid.
sub dropprivileges {
	my ($uid, $gid) = @_;

	my $failure;
	eval {
		local $SIG{__DIE__} = undef;
		# Assigning a list to $) calls setgroups(2), replacing the
		# supplementary groups with just $gid. Left alone, a root
		# supplementary group survives a correct uid/gid drop and every id
		# still reads back as dropped.
		$) = "$gid $gid";
		$( = $gid;
		POSIX::setgid($gid);
		POSIX::setuid($uid);
		1;
	} or do {
		$failure = $@ || "unknown error";
		$failure =~ s/\n.*\z//s;
		$failure =~ s/\s+\z//;
		return "the drop itself failed: ".($failure ne "" ? $failure : "no reason was reported");
	};

	return "the ids do not read back as dropped" if ($< != $uid or $> != $uid or $( != $gid or $) != $gid);

	# The saved ids are what make the drop permanent, and Perl cannot read
	# them, so they come from the kernel. Read with a plain open rather than
	# through slurp(): this is the verification step of a security control and
	# should not depend on an indirection another part of the process could
	# redirect. Fail closed on anything unreadable or unparsable -- if the drop
	# cannot be proven, the messenger must not serve.
	my %ids;
	unless (open (my $STATUS, "<", "/proc/self/status")) {
		return "cannot read /proc/self/status to verify the saved ids";
	} else {
		while (my $line = <$STATUS>) {
			if ($line =~ /^(Uid|Gid):\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/) {$ids{$1} = $4}
			if ($line =~ /^Groups:\s*(.*?)\s*$/) {$ids{Groups} = $1}
		}
		close ($STATUS);
	}

	return "the saved uid is not $uid" if (!defined $ids{Uid} or $ids{Uid} != $uid);
	return "the saved gid is not $gid" if (!defined $ids{Gid} or $ids{Gid} != $gid);

	# A surviving root supplementary group leaves the process holding group 0
	# with every id above still reading back correctly, and neither $( nor $)
	# shows it because numifying them yields their first field only. setgroups
	# installed exactly $gid, so that is what passes -- as does an empty list,
	# which some kernels and container configurations report instead and which
	# is strictly more restrictive. Anything else fails closed, a missing
	# Groups line included, because then there is nothing to verify against.
	return "the supplementary groups were not dropped" if (!defined $ids{Groups});
	my @groups = grep {$_ ne ""} split(/\s+/, $ids{Groups});
	return "the supplementary groups were not dropped" if (scalar @groups > 1);
	return "the supplementary groups were not dropped" if (scalar @groups == 1 and $groups[0] != $gid);

	return;
}
# end dropprivileges
###############################################################################
# start messengervhostsec
#
# The per-vhost security block for the MESSENGERV2 configuration, matching what
# apache.http.txt and apache.https.txt state for MESSENGERV3.
#
# The messenger document root is served to anonymous clients that the firewall
# has blocked, so the vhost must hand them nothing beyond the unblock page.
# Left as it was, the vhost granted "AllowOverride All" over MESSENGER_USER's
# home, which put every one of these decisions in a .htaccess that
# MESSENGER_USER can rewrite -- and the .htaccess csf itself wrote there asked
# for "+FollowSymLinks +ExecCGI", so CGI execution and symlink following were
# on by default in a directory that account controls.
#
# Because AllowOverride None makes any .htaccess inert, the three directives
# that file legitimately carried -- the access grant, the index list and the
# front controller rewrite -- are stated here instead, so the unblock page
# keeps working.
sub messengervhostsec {
	my ($homedir, $public_html) = @_;
	my $options = "Options -ExecCGI -Includes -IncludesNOEXEC -Indexes -MultiViews -FollowSymLinks +SymLinksIfOwnerMatch";

	my $text = "";
	$text .= " <IfModule userdir_module>\n";
	$text .= "  UserDir disabled\n";
	$text .= " </IfModule>\n";
	$text .= " <Directory \"$homedir\">\n";
	$text .= "  AllowOverride None\n";
	$text .= "  $options\n";
	$text .= " </Directory>\n";
	$text .= " <Directory \"$public_html\">\n";
	$text .= "  AllowOverride None\n";
	$text .= "  $options\n";
	$text .= "  Require all granted\n";
	$text .= "  DirectoryIndex index.php index.html index.htm\n";
	$text .= "  <IfModule mod_rewrite.c>\n";
	$text .= "   RewriteEngine On\n";
	$text .= "   RewriteCond %{REQUEST_FILENAME} !-f\n";
	$text .= "   RewriteCond %{REQUEST_FILENAME} !-d\n";
	$text .= "   RewriteRule ^ /index.php [L,QSA]\n";
	$text .= "  </IfModule>\n";
	$text .= " </Directory>\n";

	return $text;
}
# end messengervhostsec
###############################################################################
sub messengerlog {
	my $homedir = shift;
	my $message = shift;
	if ($config{DEBUG}) {
		sysopen (my $LOG, "/var/log/lfd_messenger.log", O_WRONLY | O_APPEND | O_CREAT);
		print $LOG "[$$]: ".$message."\n";
		close ($LOG);
	}
	return;
}
# end messengerlog
###############################################################################
# start childcleanup
sub childcleanup {
	$SIG{INT} = 'IGNORE';
	$SIG{TERM} = 'IGNORE';
	$SIG{HUP} = 'IGNORE';
	my $line = shift;
	my $message = shift;

	if (($message eq "") and $line) {
		$message = "Child $childproc: $line";
		$line = "";
	}

	$0 = "child - aborting";

	if ($message) {
		if ($line ne "") {$message .= ", at line $line"}
		logfile("$message");
	}
    exit;
}
# end childcleanup
###############################################################################
# start getethdev
sub getethdev {
	my $ethdev = ConfigServer::GetEthDev->new();
	my %g_ipv4 = $ethdev->ipv4;
	my %g_ipv6 = $ethdev->ipv6;
	foreach my $key (keys %g_ipv4) {
		my $netip = Net::IP->new($key);
		my $type = $netip->iptype();
		if ($type eq "PUBLIC") {$ips{$key} = 1}
	}
	if ($config{IPV6}) {
		foreach my $key (keys %g_ipv6) {
			if ($key !~ m[::1/128]) {
				eval {
					local $SIG{__DIE__} = undef;
					$ipscidr6->add($key);
				};
			}
		}
	}
	return;
}
# end getethdev
###############################################################################
# start error
sub error {
	my $error = shift;
	logfile($error);
	exit;
}
# end error
###############################################################################
# start conftree
sub conftree {
	my $fileglob = shift;
	foreach my $file (glob($fileglob)) {
		if ($file =~ /csf\.messenger\.conf$/) {next}
		if ($file =~ /\/var\/lib\/csf\/csf.conf$/) {next}
		if (-e $file) {
			if ($config{DEBUG} >= 1) {logfile("SSL: Processing [$file]")}
			my $start = 0;
			foreach my $line (slurp($file)) {
				if ($webserver eq "apache") {
					$line =~ s/\'|\"//g;
					if ($line =~ /^\s*ServerRoot\s+\"?(\S+)\"?/) {
						$serverroot = $1;
						unless (-d $serverroot) {$serverroot = ""}
					}
					if ($serverroot eq "" and -d "/etc/apache2") {$serverroot = "/etc/apache2"}
					if ($line =~ /^\s*Include\s+(\S+)/) {
						my $include = $1;
						if ($include !~ /^\//) {$include = "$serverroot/$include"}
						if ($config{DEBUG} >= 1) {logfile("SSL: Including [$include]")}
						&conftree($include);
					}
					if ($line =~ /^\s*IncludeOptional\s+(\S+)/) {
						my $include = $1;
						if ($include !~ /^\//) {$include = "$serverroot/$include"}
						if ($config{DEBUG} >= 1) {logfile("SSL: IncludeOptional [$include]")}
						&conftree($include);
					}
					if ($line =~ /^\s*<VirtualHost\s+[^\>]+>/) {
						$start = 1;
					}
					if ($start) {
						if ($line =~ /\s*ServerName\s+(\w+:\/\/)?([a-zA-Z0-9\.\-]+)(:\d+)?/) {$sslhost = $2}
						if ($line =~ /\s*ServerAlias\s+(.*)/) {$sslaliases .= " ".$1}
						if ($line =~ /\s*SSLCertificateFile\s+(\S+)/) {
							my $match = $1;
							if (-e $match) {
								$osslcert = $match;
								logfile("SSL: Found [$sslhost] certificate in [$file]");
							}
						}
						if ($line =~ /\s*SSLCertificateKeyFile\s+(\S+)/) {
							my $match = $1;
							if (-e $match) {
								$osslkey = $match;
								logfile("SSL: Found [$sslhost] key in [$file]");
							}
						}
						if ($line =~ /\s*SSLCACertificateFile\s+(\S+)/) {
							my $match = $1;
							if (-e $match) {
								$osslca = $match;
								logfile("SSL: Found [$sslhost] ca bundle in [$file]");
							}
						}
					}
					
					if ($line =~ /^\s*<\/VirtualHost\s*>/) {
						$start = 0;
						if ($sslhost ne "" and !checkip($sslhost) and $osslcert ne "") {
							if (-e $osslcert) {
								$sslcert = $ssldir."certs/".$sslhost."\.crt";
								copy($osslcert, $ssldir."certs/".$sslhost."\.crt");
							}
							if (-e $osslkey) {
								$sslkey = $ssldir."keys/".$sslhost."\.key";
								copy($osslkey, $ssldir."keys/".$sslhost."\.key");
							}
							if (-e $osslca) {
								$sslca = $ssldir."ca/".$sslhost."\.ca";
								copy($osslca, $ssldir."ca/".$sslhost."\.ca");
							}
							$ssldomains{$sslhost}{key} = $sslkey;
							$ssldomains{$sslhost}{aliases} = $sslaliases;
							$ssldomains{$sslhost}{cert} = $sslcert;
							$ssldomains{$sslhost}{ca} = $sslca;
							push @ssldomainkeys, $sslhost;
							if ($config{DEBUG} >= 1) {logfile("SSL: Found [$sslhost] in [$file]")}
						}
						$sslhost = "";
						$sslcert = "";
						$sslkey = "";
						$sslca = "";
						$osslcert = "";
						$osslkey = "";
						$osslca = "";
						$sslaliases = "";
					}
				}
				elsif ($webserver eq "litespeed") {
					$line =~ s/\'|\"//g;
					if ($line =~ /^\s*include\s+(\S+)/) {
						my $include = $1;
						$include =~ s/\$SERVER_ROOT/$serverroot/;
						$include =~ s/\$VH_NAME/$sslhost/;
						if ($include !~ /^\//) {$include = "$serverroot/$include"}
						if ($config{DEBUG} >= 1) {logfile("SSL: include [$include]")}
						&conftree($include);
					}
					if ($line =~ /^\s*configFile\s+(\S+)/) {
						my $include = $1;
						$include =~ s/\$SERVER_ROOT/$serverroot/;
						$include =~ s/\$VH_NAME/$sslhost/;
						if ($include !~ /^\//) {$include = "$serverroot/$include"}
						if ($config{DEBUG} >= 1) {logfile("SSL: configFile [$include]")}
						&conftree($include);
					}
					if ($line =~ /^\s*virtualHost\s+([^\{]+)\s+\{/) {
						my $newsslhost = $1;
						if ($newsslhost ne "" and $config{DEBUG} >= 1) {logfile("SSL: Found [$newsslhost] in [$file]")}
						if ($litestart == 1) {
							if ($sslhost ne "" and $osslcert ne "") {
								if (-e $osslcert) {
									$sslcert = $ssldir."certs/".$sslhost."\.crt";
									copy($osslcert, $ssldir."certs/".$sslhost."\.crt");
								}
								if (-e $osslkey) {
									$sslkey = $ssldir."keys/".$sslhost."\.key";
									copy($osslkey, $ssldir."keys/".$sslhost."\.key");
								}
								if (-e $osslca) {
									$sslca = $ssldir."ca/".$sslhost."\.ca";
									copy($osslca, $ssldir."ca/".$sslhost."\.ca");
								}
								$sslaliases =~ s/\$VH_NAME/$sslhost/;
								$ssldomains{$sslhost}{key} = $sslkey;
								$ssldomains{$sslhost}{aliases} = $sslaliases;
								$ssldomains{$sslhost}{cert} = $sslcert;
								$ssldomains{$sslhost}{ca} = $sslca;
								push @ssldomainkeys, $sslhost;

								$sslhost = "";
								$sslcert = "";
								$sslkey = "";
								$sslca = "";
								$osslcert = "";
								$osslkey = "";
								$osslca = "";
								$sslaliases = "";
							}
						}
						$litestart = 1;
						$sslhost = $newsslhost;
					}
					if ($litestart) {
						if ($line =~ /\s*vhDomain\s+(\w+:\/\/)?([a-zA-Z0-9\.\-]+)(:\d+)?/) {$sslhost = $2}
						if ($line =~ /\s*vhAliases\s+(.*)/) {$sslaliases .= " ".$1}
						if ($line =~ /\s*certFile\s+(\S+)/) {
							my $match = $1;
							if (-e $match) {
								$osslcert = $match;
								logfile("SSL: Found [$sslhost] certificate in [$file]");
							}
						}
						if ($line =~ /\s*keyFile\s+(\S+)/) {
							my $match = $1;
							if (-e $match) {
								$osslkey = $match;
								logfile("SSL: Found [$sslhost] key in [$file]");
							}
						}
					}
				}
			}
		}
	}
	return;
}
# end conftree
###############################################################################

1;
