What is it?
-----------
A way to grab Seculert's Crime Servers and Threat Intelligence Records
(via their API) and push them into QRadar's Remote Networks, which
then you can build Rules uppon. The beauty of this is that in reality
it shows you how to more generally push custom "BAD" IPs/Networks into
QRadar and auto-deploy them. You can use any list of IPs/networks. If
it's CSV, it should be an absolute breeze to import.



How does it work?
-----------------
You need to go into 'seculert_qradar.pl' and edit the '#START USER
CONFIG' section. The first variable you will see is the "seculert" api
key - which you can get from your Seculert account (fantastic service
http://seculert.com), but again, this can be easily be any
CSV list. (Please see bellow about CSV) The idea is that you download both feeds and convert them
into the "IP" format that QRadar understands with the "Network" (in
this case 'SECULERT') ID and the Sub-ID (in this case 'CS' and 'TIR').
Then you pull the existing remotenet.conf file, and prune out the old
SECULERT list, and then merge in the new one that you just pulled.
Then you upload the new file back to QRadar and auto-trigger the
deployment (here is the real qradar magic).



What is assumed?
----------------
1.) Acess to the following linux binaries: perl (duh!), ssh/scp, lynx
(note: lynx because Perl seems to have a big problem currently with
HTTPS 'CONNECT' calls over a Proxy. Please see the notes within the
script.

2.) You have dropped public ssh key under: $qradar_console:/root/.ssh/authorized_keys2

3.) You have dropped private ssh key under: $seculert_dir/qr-id_dsa

4.) You will add your environment variables in the '# START USER CONFIG' section

5.) Per the code, you are only looking back 30 days in terms of the
Seculert feed. This is because something could be 'first seen' 5+ months ago
and then fixed a month later, and last seen '4+' months ago. It would
produce false results if we just blanket target everything.


OK, I have the IPs, now what?
-----------------------------
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
non-included Perl modules (currently 1 - Date Calculations)

2.) The idea is that this will run on a cron.

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
my $source = 'BAD-IP-Addresses';
my $type_description = 'honeypots';

open(FP, 'your-csv-file.csv')
for my $line (<FP>) {
	my ($hostname, $ip, $something1, $something2) = split(/,/, $line);
	print OUT "$source $type_description $ip #FF0000 0 90  29\n";
}
close(FP);
```

Soon to come: URL for modified version.



Credits?
--------
Xavier Ashe - without his input on the QRadar deployment trigger I
would have never been able to get this to work fully automatically.
