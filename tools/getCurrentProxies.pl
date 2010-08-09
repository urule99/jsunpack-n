#!/usr/bin/perl -w 

use LWP::Simple; 
use LWP::UserAgent; 
use HTTP::Request::Common; 

my $ua = new LWP::UserAgent; 
$ua->agent("Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1"); 

my $req = new HTTP::Request GET => 'http://www.malwaregroup.com/Proxies'; 
my $res = $ua->request($req); 
my $proxies = $res->content;

open (STDOUT, ">> proxies.txt"); 

if (defined $proxies){
    @data = $proxies;
    foreach $line (@data){
        if ($line =~ /\">([\d\.]{7,}.*?)\<\/a\>\<\/td\>\s\<td\>(.*?)\<\/td\>/i){
            while ($line =~ m/\">([\d\.]{7,}.*?)\<\/a\>\<\/td\>\s\<td\>(.*?)\<\/td\>/ig){
                print "$1:$2,";
            }
        } else {
            print "Fail\n";
        }
    }
}

         
