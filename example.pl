#!/usr/bin/perl

use strict;
use warnings;

use cifvirustotal;

use Data::Dumper;

my $options = {
	apikey => '17cea83b713c5f39611c918a0aa2666c3581326c9181e8fa1f563373860297bb',
};

my $cifvt = cifvirustotal::new($options);

my $filename = "somename.exe";
my $binary = "akjs9d789ufas89df7a0s89dfhzy6v7dfvjisdfvx8df769s7dfnvbsdlfju6y897dsfv9dnhjfkv";
#my $res = $cifvt->scan_binary_string($filename,$binary);
my $resource_id = "a5f3d91ec4a67e3cada561f25bf1fd0089c471fd93ddafa59def5f5f777b2140";
my $res = $cifvt->retrieve_file_report($resource_id);
print Dumper($res);