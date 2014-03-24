#!/usr/bin/perl
#
# Kippo2MySQL v0.2
#
# A simple script to populate a MySQL database
# with data extracted from Kippo honeypot's logs.
# 
# This is useful when your honeypot runs on a low-end
# machine like a small VPS and mysql-server is not an option.
# You can compress all of your logs, move them to a more capable
# machine and then use kippo2mysql.pl to populate your database.
#
# A simple web interface for the results will be published soon
# on the website mentioned below.
#
# Please leave feedback at: bruteforce.gr/kippo2mysql
#
# This file is a modified version of kippo-stats perl script
# originally writen by Tomasz Miklas and modified by mig5.
#  
# This file is distributed under the terms of GPLv3.
#

#use strict;
#use warnings; #enable for debugging
use DBI;

#Paths to various kippo components - change accordingly!
#
#Data directory
my $kippodatadir = '/home/user/kippo/data';
#Config directory
my $kippoconfdir = '/home/user/kippo';
#Log directory
my $kippologdir = '/home/user/kippo/log';

my $date = $ARGV[0] || 'Lifetime';
 
my (%sources, %usernames, %passwords, %sshversions, %userpasscombo);
my ($left,$right,$cnt,$connections);
my $sensorid = `md5sum $kippoconfdir/kippo.cfg | cut -d " " -f 1`;

#MySQL server values - change accordingly!
$sql_user = 'username';
$sql_password = 'password';
$database = 'database';
$hostname = 'localhost';
$port = '3306';

#Connect to the database
$dbh = DBI->connect("dbi:mysql:database=$database;host=$hostname;port=$port", $sql_user, $sql_password);

#Drop previously created tables (if any)
$SQL = "drop table hosts;";
$DROP = $dbh->do($SQL);
$SQL = "drop table clients;";
$DROP = $dbh->do($SQL);
$SQL = "drop table auth;";
$DROP = $dbh->do($SQL);

#Create the required database tables
$SQL = "create table hosts(ID integer primary key auto_increment, ip text not null)";
$CreateTable = $dbh->do($SQL);
$SQL = "create table clients(ID integer primary key auto_increment, client text not null)";
$CreateTable = $dbh->do($SQL);
$SQL = "create table auth(ID integer primary key auto_increment, username text not null, password text not null)";
$CreateTable = $dbh->do($SQL);

print "\n\tKippo2MySQL: a simple script to populate a MySQL database with data from Kippo log files.\n";
print "\n\tPlease ignore the warnings you might see, some values might cause problems,\n\tbut the procedure will continue anyway.\n";
print "\n\tDepending on the size of your logs this operation might take some minutes,\n\tseat back and relax, don't worry if your terminal seems idle for a long time.\n\n";
sleep(3);

#Start parsing Kippo log files...
open (IN, "cat $kippologdir/kippo* |") || die "Can't open log stream: $!\n";
while (<IN>) {
  next if $date ne 'Lifetime' and !/^$date/;
  next if !/(login attempt|New connection:|Remote SSH version:)/;
  chomp;
  # New connection: xx.xx.xx.xx:<port>
  # Remote SSH version: SSH-2.0-libssh-0.1
  # login attempt [nurmi/nurmi] failed
  if (/New connection: (.*?):/) { 
	$sources{$1}++;
	$connections++;
	$SQL = "insert into hosts (ip)" .
	" values('$1')";
	$InsertRecord = $dbh->do($SQL);
  };
  if (/Remote SSH version:\s+(.*?)$/) {
	$sshversions{$1}++;
	$SQL = "insert into clients (client)" .
        " values('$1')";
        $InsertRecord = $dbh->do($SQL);
  };
  if (/login attempt \[(.*?)\/(.*?)\]/) { 
	$usernames{$1}++; 
	$passwords{$2}++; 
	$userpasscombo{"$1 / $2"}++; 
	$SQL = "insert into auth (username, password)" .
        " values('$1', '$2')";
        $InsertRecord = $dbh->do($SQL);
  };
}
close (IN);

print "--------------------------------------------------------------\n\n"; 
print "$date stats for kippo instance\nInstance $sensorid\nUnique values ($connections connections):\n - usernames\t" , scalar keys %usernames , "\n - passwords\t" , scalar keys %passwords , "\n - sources\t" , scalar keys %sources , "\n";
print "--------------------------------------------------------------\n";