#!/usr/bin/perl
#############################################################################
# Copyright (c) 2012, Harvard University IT Security - Ventz Petkov <ventz_petkov@harvard.edu>
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
# Last: 01-15-13
# Comment: Push "BAD" IPs/Networks into QRadar's "Remote Networks",
# tag them properly, and use them!
# Assumptions:
# 	Acess to the following linux binaries: perl (duh!), ssh/scp, lynx
# 		(note: lynx because Perl seems to have a big problem currently
# 		with HTTPS 'CONNECT' calls over a Proxy. Please see the notes
# 		within the script.
#	You have dropped public ssh key under: $qradar_console:/root/.ssh/authorized_keys2
#   You have dropped private ssh key under: $seculert_dir/qr-id_dsa

use Date::Calc qw(Add_Delta_DHMS);

#####################################################################
# START USER CONFIG #

my $seculert_api_key = 'API-KEY';

# Proxy used to reach SECULERT API Only
# valid formats:
#	'0' - disable proxy
#	'1' - enable proxy
$proxy = 0;
$proxy_url = 'http://proxy.domain.com:8080';

# Seculert default work dir and "bad ip" file for qradar
my $seculert_dir = '/usr/local/seculert';
my $seculert_qradar_list = "$seculert_dir/seculert.txt";

# NOTE: You must have an SSH key set for 'root'
my $qradar_console = 'qradar-console.domain.com';
my $qradar_ssh_key = "$seculert_dir/qr-id_dsa";

# Don't need to modify knownhosts
my $qradar_ssh_knownhosts = "$seculert_dir/known_hosts";

# Don't need to modify days_back
# Number of days to go back for Malicious IPs "LastSeen"
# NOTE: This means IPs that have been "LastSeen" 31 days ago will NOT
# be included in the final IP list.
my $days_back = 30;

# valid types:
#	'1' = Crime Servers
#	'2' = Threat Intelligence Records

# Don't need to modify seculert_types - includes both by default
# List any combination of just '1', '1 and 2', or just '2'
# Examples: (1) or (1,2) or (2,1) or (2)
my @seculert_types = (1,2);

# END USER CONFIG #
#####################################################################

chdir($seculert_dir);


# Grab Today's date
($s,$m,$h,$day,$month,$year,$wday,$yday,$isdst) = localtime(time);
$month += 1; $year += 1900;

# Back days - grab ONLY information for last-seen that's at least from
# -$days_back. See top '$days_back' for additional information.
my ($byear, $bmonth, $bday, $bhour, $bmin, $bsecond) = Add_Delta_DHMS($year, $month, $day, $h, $m, $s, -$days_back, 0, 0, 0); 

# Format it for Seculert API
my $date_back = "$bmonth/$bday/$byear";

# Our QRadar result file
open(OUT, ">>$seculert_qradar_list");

for my $seculert_type (@seculert_types) {
	# Get a human readable description
	my $type_description = '';
	my $seculert_api_url = '';
	if($seculert_type == 1) {
		$type_description = 'CS';
		$seculert_api_url = "https://portal.seculert.com/getinfo.aspx?key=$seculert_api_key&format=sys&type=$seculert_type&filter={'f_0_field':'LastSeen','f_0_data_type':'date','f_0_data_comparison':'gt','f_0_data_value':'$date_back'}&field=FirstSeen&dir=DESC";
	}
	elsif($seculert_type == 2) {
		$type_description = 'TIR';
		$seculert_api_url = "https://portal.seculert.com/getinfo.aspx?key=$seculert_api_key&format=sys&type=$seculert_type&filter={'f_0_field':'Timestamp','f_0_data_type':'date','f_0_data_comparison':'gt','f_0_data_value':'$date_back'}&field=Timestamp&dir=DESC";
	}

	
	# NOTE: this is used sadly instead of WWW::Mechanize OR LWP::Agent
	# because of the PROXY HTTPS request issue (CONNECT) vs (GET)
	# Read up on this - it's a huge problem in perl!
	# 	google: 'lwp proxy Unsupported Request Method and Protocol'
	# Also, Crypt::SSLeay doesn't seem to work as advertised and
	# that's one of the few solutions that should work
	# IF Anyone can figure out how to fix this, please email me: ventz@vpetkov.net
	if($proxy) { $ENV{'HTTPS_PROXY'} = "$proxy_url"; }
	my @page = `lynx -dump \"$seculert_api_url\"`;


	for my $line (@page) {
		my ($hostname, $ip, $first_seen, $last_seen) = split(/,/, $line);
		$ip =~ s/"//g; $ip .= '/32';
		print OUT "SECULERT $type_description $ip #FF0000 0 90  29\n";
	}
}

close(OUT);

# SSH To QRadar's Console and push out file + trigger update
`scp -i $qradar_ssh_key -o UserKnownHostsFile=$qradar_ssh_knownhosts -o StrictHostKeyChecking=no root\@$qradar_console:/store/configservices/staging/globalconfig/remotenet.conf .`;
`sed -i -e '/^SECULERT/d' remotenet.conf`;
`cat $seculert_qradar_list >> remotenet.conf`;
`scp -i $qradar_ssh_key -o UserKnownHostsFile=$qradar_ssh_knownhosts -o StrictHostKeyChecking=no remotenet.conf root\@$qradar_console:/store/configservices/staging/globalconfig/remotenet.conf`;

# Remove our SECULERT list and the newly pushed out qradar conf
unlink($seculert_qradar_list); unlink ('remotenet.conf');

# QRadar magic
my $host_token = `ssh -i $qradar_ssh_key -o UserKnownHostsFile=$qradar_ssh_knownhosts -o StrictHostKeyChecking=no root\@$qradar_console 'cat /opt/qradar/conf/host.token'`;
`ssh -i $qradar_ssh_key -o UserKnownHostsFile=$qradar_ssh_knownhosts -o StrictHostKeyChecking=no root\@$qradar_console 'wget -q -O - --header "SEC:$host_token" --no-check-certificate \"https://localhost/console/JSON-RPC?{id:'',method:'QRadar.scheduleDeployment',params:[{fullDeploy:false},{queued:false}]}\"'`;


1;



########################################################################
# SEE SSL THROUGH PROXY NOTE above

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
