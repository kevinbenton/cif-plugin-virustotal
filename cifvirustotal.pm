package cifvirustotal;

use strict;
use warnings;
use File::Temp;
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
	my $vtapi = $options->{'apikey'};

	my $self = bless {
		vtkey => $vtapi
	};
	return $self;
}


sub dance {
	my $self = shift;
	print Dumper($self->{'vtapi'});
	return;
}

sub scan_binary_string {
	my $self = shift;
	my $filename = shift;
	my $binarystring = shift;
	my $content = ['apikey' => $self->{'vtkey'},'file' => [undef,$filename,'Content_Type' => 'application/binary','Content'=>$binarystring]];
	my $url = 'https://www.virustotal.com/vtapi/v2/file/scan';
	my $res = $self->post_to_vt($url,$content);
	die Dumper($res); 
	return $res;
}



sub retrieve_file_report {
	my $self = shift;
	my $identifier = shift;
	my $content = ['apikey' => $self->{'vtkey'},'resource' => $identifier];
	my $url = 'https://www.virustotal.com/vtapi/v2/file/report';
	my $res = $self->post_to_vt($url,$content);
	die Dumper($res); 
	return $res;
}


sub retrieve_url_report {
	my $self = shift;
	my $identifier = shift;
	
	my $res = $self->{'vtapi'}->get_url_report($identifier);
	
	return $res;	
}


sub post_to_vt {
	my $self = shift;
	my $apiurl = shift;
	my $content = shift;
	my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 1 });
	my $httpresponse = $ua->post( $apiurl, Content_Type => 'multipart/form-data', Content => $content );
	die "API error: ", $httpresponse->status_line unless($httpresponse->is_success);
	my $json = JSON->new->allow_nonref->decode($httpresponse->content);   
	return $json;
}

1;
