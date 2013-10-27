#!/usr/bin/perl
#############################################################################
# Copyright (c) 2013, Harvard University IT Security - Ventz Petkov <ventz_petkov@harvard.edu>
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#  
# 1.	Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
# 
# 2.	Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# 
# 3.	Neither the name of the Harvard University nor the names of its
# contributors may be used to endorse or promote products derived from this
# software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#############################################################################

############
# By: Ventz Petkov (ventz_petkov@harvard.edu)
# License: BSD 3
# Date: 12-11-12
# Last: 10-26-13
# Comment: Push "BAD" IPs/Networks into QRadar's "Remote Networks",
# tag them properly, and use them!
# Assumptions:
# 	Acess to the following linux binaries: perl (duh!), ssh/scp, lynx
# 		(note: lynx because Perl seems to have a big problem currently
# 		with HTTPS 'CONNECT' calls over a Proxy. Please see the notes
# 		within the script.
#	You have dropped public ssh key under: $qradar_console:/root/.ssh/authorized_keys2
#   You have dropped private ssh key under: $seculert_dir/qr-id_dsa
#   You have set: $seculert_api_key | $qradar_console_host | $proxy and $proxy_url (optional)

#!/usr/bin/perl -w
use strict;

use Date::Calc qw(Add_Delta_DHMS);
use JSON;
# (Ubuntu: libjson-perl)

#####################################################################
# START USER CONFIG #

# MUST change to get started:
# $seculert_api_key | $qradar_console_host | $proxy and $proxy_url (optional)

my $seculert_api_key = 'SECULERT-API-KEY-CHANGEME';
my $securlert_api_url = 'https://seculert-prod.apigee.net/v2';

# Proxy used to reach SECULERT API Only
# valid formats:
#	'0' - disable proxy
#	'1' - enable proxy
my $proxy = 1;
my $proxy_url = 'http://proxy.domain.tld:8080';

# Seculert default work dir and "bad ip" file for qradar
my $seculert_dir = '/usr/local/seculert';
my $seculert_qradar_list = "$seculert_dir/seculert.txt";

# NOTE: You must have an SSH key set for 'root'
my $qradar_console = 'qradar-console.domain.tld';
my $qradar_ssh_key = "$seculert_dir/qr-id_dsa";
my $qradar_ssh_knownhosts = "$seculert_dir/known_hosts";

# Number of days to go back for Malicious IPs "last-seen"
# NOTE: This means IPs that have been "last-seen" 31 days ago will NOT
# be included in the final IP list.
my $days_back = 30;

# valid types:
#	'1' = Crime Servers
#	'2' = Botnet Interception Records

# List any combination of just '1', '1 and 2', or just '2'
# Examples: (1) or (1,2) or (2,1) or (2)
my @seculert_types = (1,2);

# END USER CONFIG #
#####################################################################

chdir($seculert_dir);


# Grab Today's date
my ($s,$m,$h,$day,$month,$year,$wday,$yday,$isdst) = localtime(time);
$month += 1; $year += 1900;

# Back days - grab ONLY information for last-seen that's at least from
# -$days_back. See top '$days_back' for additional information.
my ($byear, $bmonth, $bday, $bhour, $bmin, $bsecond) = Add_Delta_DHMS($year, $month, $day, $h, $m, $s, -$days_back, 0, 0, 0); 


# Format Year, Month, Date - proper # of digits:
$byear = sprintf("%04d", $byear);
$bmonth = sprintf("%02d", $bmonth);
$bday = sprintf("%02d", $bday);

$year = sprintf("%04d", $year);
$month = sprintf("%02d", $month);
$day = sprintf("%02d", $day);

# Format it for Seculert API
my $from_date = "$byear-$bmonth-$bday";
my $to_date = "$year-$month-$day";

# Our QRadar result file
open(OUT, ">>$seculert_qradar_list");

print "Downloading from Seculert API...\n";
for my $seculert_type (@seculert_types) {
	my $type_description;
	my $seculert_api_url;
    my $json_container_name;
    my $json_ip_field_name;

	if($seculert_type == 1) {
		$type_description = 'CS';
        $json_container_name = 'crime-servers';
        $json_ip_field_name = 'ip-address';
		$seculert_api_url = "$securlert_api_url/CrimeServers?api_key=$seculert_api_key&from_date=$from_date&to_date=$to_date";
	}
	elsif($seculert_type == 2) {
	    $type_description = 'BIR';
        $json_container_name = 'incidents';
        $json_ip_field_name = 'source-ip';
		$seculert_api_url = "$securlert_api_url/BotnetInterception?api_key=$seculert_api_key&from_date=$from_date&to_date=$to_date";
	}


    # See note at bottom on why we have to use lynx vs Perl Module
	if($proxy) { $ENV{'https_proxy'} = "$proxy_url"; }
	my $decoded = decode_json(`lynx -dump \"$seculert_api_url\"`);

    my @servers = @{$decoded->{$json_container_name}};


    # QRadar remotenet.conf syntax (per IBM support):
    # NOTE: this is the "OUT" file.
    # 1 - Name
    # 2 - Sub-Name
    # 3 - IP Address
    # 4 - is colour, deprecated
    # 5 - database length, deprecated
    # 6 - asset weight, deprecated
    # 7 - an ID for the 'record' each unique name pair (first 2 columns) gets an ID

    print "Writing QRadar format (for: $type_description)...\n";
    for my $server (@servers) {
        my $ip = $server->{$json_ip_field_name}.'/32';
        print OUT "SECULERT $type_description $ip #FF0000 0 90  29\n";
    }
}

close(OUT);

print "Sending to QRadar...\n";
# SSH To QRadar's Console and push out file + trigger update
`scp -i $qradar_ssh_key -o UserKnownHostsFile=$qradar_ssh_knownhosts -o StrictHostKeyChecking=no root\@$qradar_console:/store/configservices/staging/globalconfig/remotenet.conf .`;
`sed -i -e '/^SECULERT/d' remotenet.conf`;
`cat $seculert_qradar_list >> remotenet.conf`;
`scp -i $qradar_ssh_key -o UserKnownHostsFile=$qradar_ssh_knownhosts -o StrictHostKeyChecking=no remotenet.conf root\@$qradar_console:/store/configservices/staging/globalconfig/remotenet.conf`;

print "Cleaning up...\n";
# Remove our SECULERT list and the newly pushed out qradar conf
unlink($seculert_qradar_list); unlink ('remotenet.conf');

print "Deploying in QRadar...(takes time to complete)\n";
# QRadar magic
`ssh -i $qradar_ssh_key -o UserKnownHostsFile=$qradar_ssh_knownhosts -o StrictHostKeyChecking=no root\@$qradar_console /opt/qradar/upgrade/util/setup/upgrades/do_deploy.pl`;
print "Complete!\n\n";


1;



########################################################################
# The reason why I use lynx:

# NOTE: this is used sadly instead of WWW::Mechanize OR LWP::Agent
# because of the PROXY HTTPS request issue (CONNECT) vs (GET)
# Read up on this - it's a huge problem in perl!
# 	google: 'lwp proxy Unsupported Request Method and Protocol'
# Also, Crypt::SSLeay doesn't seem to work as advertised and
# that's one of the few solutions that should work
# IF Anyone can figure out how to fix this, please email me: ventz@vpetkov.net

# What I've tried:


	#my $mech = WWW::Mechanize->new(ssl_opts => {verify_hostname => 0,});
	# if($proxy) { $mech->proxy(['http', 'https'], "$proxy_url"); }
	#$mech->agent_alias( 'Mac Safari' );
	#$mech->get($seculert_api_url);
	#my @page = $mech->content;

	# vs

	#my $ua  = LWP::UserAgent->new;
	# if($proxy) { $ENV{'HTTPS_PROXY'} = "$proxy_url"; }
	#$ua->ssl_opts(verify_hostname => 0);
	#$ua->timeout(15);
	#my $response = $ua->get("$seculert_api_url");
	#if ($response->is_success) {
	#	my @page = print $response->decoded_content;
	#}
	#else {
	#	die $response->status_line;
	#}
########################################################################
