package cifvirustotal;

use strict;
use warnings;
use File::Temp;
#use lib '../mmdef-pb-perl/lib/';
#use lib '../vt-api-perl/lib/';
use MMDEF::Pb::Simple;
use VT::API;

use LWP::UserAgent;
use Net::SSLeay;
use JSON;

use Data::Dumper;




sub new {
	my $options = shift;
	
	if (!defined $options->{'apikey'}){
		warn("VT API key must be provided to use the cif virus total plugin");
		return 0;
	}
	my $vtapi = VT::API->new(key=>$options->{'apikey'});

	my $self = bless {
		vt=> $vtapi,
		res => {}
	};
	return $self;
}

sub scan_binary_string {
	my ($self,$args) = @_;
	die('missing required argument "filename" in arguments passed to scan_binary_string') unless(defined $args->{'filename'});
	die('missing required argument "binarydata" in arguments passed to scan_binary_string') unless(defined $args->{'binarydata'});
	$self->{res} = $self->{vt}->scan_binary_string($args->{'binarydata'},$args->{'filename'});
	return $self->{res};
}

sub scan_url {
	my ($self,$url) = @_;
	$self->{res} = $self->{vt}->scan_url($url);
	return $self->{res};
}


sub retrieve_file_report {
	my ($self,$identifier) = @_;
	$self->{res} = $self->{vt}->get_file_report($identifier);
	return $self->{res};
}


sub retrieve_url_report {
	my ($self,$identifier) = @_;
	$self->{res} = $self->{vt}->get_url_report($identifier);
	return $self->{res};
}


sub to_protobuf {
	my $self = shift;
	my $response = shift;
	$response = $self->{res} unless(defined $response);
	my $obj = undef;
	my $isfile = 0;
	if (!defined $response->{url}){
		#file object
		$isfile = 1;
		$obj = {	
			Otype=>'file',
			id=>$response->{sha256},
			md5=>$response->{md5},
			sha1=>$response->{sha1},
			sha256=>$response->{sha256},
		};
	} else {
		#URI object
		$obj = { 
			Otype=>'uri',
			uriString=>$response->{url},
			id=>$response->{url}
		};
	}
	my $objects = [$obj];
	my $relationships = [];
	foreach (keys %{$response->{scans}}){
		my $scanner = $_;
		my $co = { 
		  Otype=>'classification',
		  companyName=>$scanner,
		  id=>$scanner,
		  type=>'neutral', #can be clean, dirty, neutral, unknown, unwanted
		  classificationDetails=>{}
		};
		$co->{classificationDetails}->{definitionVersion} = $response->{scans}->{$_}->{version} if ($response->{scans}->{$_}->{version});
		if ($response->{scans}->{$_}->{result} && $isfile){
			if ($isfile){
				$co->{type}='dirty';
				$co->{classificationName} = $response->{scans}->{$_}->{result};
				$co->{classificationDetails}->{productVersion} = $response->{scans}->{$_}->{version};
				$co->{classificationDetails}->{definitionVersion} = $response->{scans}->{$_}->{update};
				$co->{classificationDetails}->{product} = $scanner;
			} else {
				$co->{type}='dirty' if($response->{scans}->{$_}->{result} =~ /malicious/);
				$co->{type}='neutral' if($response->{scans}->{$_}->{result} =~ /unrated/);
				$co->{type}='clean' if($response->{scans}->{$_}->{result} =~ /clean/);
				$co->{classificationDetails}->{product} = $scanner;
			}
		} else {
			$co->{classificationDetails}->{product} = $scanner;
			$co->{classificationName} = 'URL Scan';
		}
		push(@{$objects},$co);
		my $relationship = {
			source => $obj->{id},
			target => $scanner, 
			timestamp => $response->{scan_date},
			type => 'isClassifiedAs'
		};
		push(@{$relationships},$relationship);
	}
	my $x = MMDEF::Pb::Simple->new({
		company => 'Virus Total',
		author      => 'Virus Total',
		comment => $response->{permalink},
		id => $response->{scan_id},
		objects => $objects,
		relationships => $relationships,
	});
	return $x->encode();
}

1;
