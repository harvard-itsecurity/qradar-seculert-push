What is it?
-----------
A way to grab Seculert's "Crime Servers" and what Seculert now calls
"Botnet Interception Records" (old name was "Threat Intelligence Records")
via their new REST API, and push them into QRadar's Remote Networks.

More generally however, other than a drop in solution for Seculert to
QRadar, this is a general framework for pushing ANY source of "BAD
IPs" data into QRadar, and auto deploy. For example, if you have a
CSV (see on bottom)/XML/JSON list, it should be a breeze to import.



How does it work?
-----------------
You need to go into 'seculert_rest_qradar.pl' and edit the '#START USER
CONFIG' section. The first variable you will see is the "seculert api
key" - which you can get from your Seculert account (fantastic service
http://seculert.com).

If you don't have a Seculert account, you can pull your data from
almost any format (CSV/XML/JSON). For CSV example, see bellow.

The general idea is as follows:
You download both sets of feeds from Seculert (or load in your list of
IPs), and convert them into the "IP format" that QRadar understands
with the "Network" (in this case 'SECULERT') ID and the Sub-ID (in
this case 'CS' and 'BIR'). Then you pull the existing remotenet.conf
file, prune out the old SECULERT list, and then merge in the new one
that you just pulled. At last, you upload the new file back to QRadar
and auto-trigger the deployment (here is the real qradar magic).



What is assumed and How to get this to work (CONFIGS)
-----------------------------------------------------
1.) Access to the following linux binaries: perl (duh!), ssh/scp, lynx
(note: lynx because Perl seems to have a big problem currently with
HTTPS 'CONNECT' calls over a Proxy - lease see the notes within the
script)

2.) Perl Modules: Date::Calc (just for Add_Delta_DHMS), and JSON.

3.) You have dropped public ssh key under: $qradar_console_host:/root/.ssh/authorized_keys2

4.) You have dropped private ssh key here: $seculert_dir/qr-id_dsa

5.) You will at least change these in the '# START USER CONFIG' section:
$seculert_api_key | $qradar_console_host | $proxy and $proxy_url (optional)

6.) Per the code, you are only looking back 30 days in terms of the
Seculert feed. The reason it's 30 (or another #) vs ALL is because
let's say something is 'first seen' 5+ months ago and then fixed a
month later. The last seen would be '4+' months ago. For that reason,
it would produce false results if just look at everything.


OK, I have the IPs in QRadar, Now What?
---------------------------------------
In QRadar, first make sure the networks are visible:
Admin -> Remote Networks (find 'Section' and 'Sub-Section') that you
pushed

Now, in order to do something with this information:
Offenses -> Rules -> Action -> New Event Rule -> (next) -> (next) ->
Test Group ->  Network Property Tests -> 
select 2nd line (source IP...any...remote network locations) -> 
and then you can click on 'remote network locations' and select 
"SECULERT" (or just the "CS" or "TIR")

At this point, you can create alerts and other things to create
offenses/emails/etc...



Goals?
------
1.) If you modify this, please make sure you use the least amount of
non-included Perl modules (currently 2 - Date Calculations and JSON)

2.) The idea is that this will run from a cron job
ex:
0 0 * * * /usr/local/scripts/seculert_rest_qradar.pl > /dev/null 2>&1

3.) The goal was to make this as simple and as functional as possible.



Contact?
--------
If you need help setting this up or you find bugs, please feel free to
contact me: ventz_petkov@harvard.edu (or just fork a copy and fix the
issue :))



How can I modify this so that I can input any CSV?
--------------------------------------------------
At minimum, JUST to get it to work "as is", you would have to at least take out this block:

```perl
for my $seculert_type (@seculert_types) {
...
}
```


Let's say your CSV looks like this: hostname, ip, something1, something2"

$source would be the SOURCE name/label of the Ips
$type_description  would be the sub-name/sub-label of the SOURCE for the Ips

and modify it with:

```perl
my $source = 'BAD-IP-Addresses-LABEL';
my $type_description = 'honeypots-for-examnple';

open(FP, 'your-csv-file.csv')
for my $line (<FP>) {
	my ($hostname, $ip, $something1, $something2) = split(/,/, $line);
	print OUT "$source $type_description $ip #FF0000 0 90  29\n";
}
close(FP);
```



Credits?
--------
* Xavier Ashe - without his input on the QRadar deployment trigger I
would have never been able to get this to work fully automatically.
This trigger is long gone at this point, but some of the original guys
at Q1 have pointed me at the new 'admin' scripts for auto-deploy.

* IBM for giving me a walk-thru on the QRadar remotenet.conf syntax
details. I had guessed most of these, but they definitely filled in
a few holes for me.
