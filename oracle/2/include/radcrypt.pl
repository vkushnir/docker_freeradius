#! /usr/bin/perl -w
use strict;
use Digest::MD5;
use Digest::SHA;
use MIME::Base64;
use Getopt::Long qw(:config ignore_case permute auto_help);

sub hashCrypt {
	my($pass, $salt) = @_;
	unless(($pass)&&($salt)){
		print STDERR "Please supply a password and salt to create a salted CRYPT hash form.\n";
		exit;
	}
	print "\nCrypt-Password := ".crypt($pass,$salt)."\n\n";
}

sub hash {
	my($mode, $ctx, $pass, $salt) = @_;
	unless($pass){
		print STDERR "Please supply a password and/or salt to create a ".$mode." form.\n";
		exit;
	}
	$ctx->add($pass);
	if ($salt){
		$ctx->add($salt);
		print "\nS".$mode."-Password := ".encode_base64($ctx->digest.$salt ,'')."\n\n";
	} else {
		print "\n".$mode."-Password := ".encode_base64($ctx->digest,'')."\n\n";
	}
}

sub setPass {
	my ($opt) = @_;

	if (our $opt_pass eq '') {
		$opt_pass = $opt
	} elsif (our $opt_salt eq '') {
		$opt_salt = $opt
	} else {
		print STDERR ("Too much arguments!\n");
		exit;
	}
}

sub help {
	print <<HELP;

Usage: radcrypt.pl [options] <password> [salt]

  options:
    -crypt  Crypt hash mode
    -md5    MD5 hash mode       (default)
    -sha    SHA1 hash mode

    -p | --password=<password>  password to generate hash
    -s | --salt=<salt>          salt to add to generated hash

HELP
	exit;
}

our $opt_crypt = 0;
our $opt_md5 = 0;
our $opt_sha = 0;
our $opt_pass = '';
our $opt_salt = '';

GetOptions ('crypt', 'md5', 'sha', 
	'password=s', 'salt:s', 
	'<>' => \&setPass, 'help|?' => \&help) or die "Use --help for options\n";

unless ($opt_pass){
	print STDERR "Use --help for options\n";
	exit;
}

if ($opt_crypt+$opt_md5+$opt_sha > 1){
	print STDERR ("Please select only one HASH algoritm!\n");
	exit;
} elsif ($opt_crypt+$opt_md5+$opt_sha == 0){
	$opt_md5 = 1
}

if ($opt_crypt){
	hashCrypt($opt_pass, $opt_salt)
} elsif ($opt_md5) {
	hash('MD5', Digest::MD5->new, $opt_pass, $opt_salt)
} elsif ($opt_sha) {
	hash('SHA', Digest::SHA->new, $opt_pass, $opt_salt)
}
