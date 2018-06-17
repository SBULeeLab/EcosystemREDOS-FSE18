#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Given results from test-pattern-for-redos.pl,
#   estimate the blow-up from the various detector recommendations.
#
# Dependencies:
#   - ECOSYSTEM_REGEXP_PROJECT_ROOT must be defined

use strict;
use warnings;

use JSON::PP; # I/O
use Carp;

# Check dependencies.
if (not defined $ENV{ECOSYSTEM_REGEXP_PROJECT_ROOT}) {
  die "Error, ECOSYSTEM_REGEXP_PROJECT_ROOT must be defined\n";
}

my $fitCurve = "$ENV{ECOSYSTEM_REGEXP_PROJECT_ROOT}/analyze-regexps/redos/curve-fitting/fit-curve.py";

for my $script ($fitCurve) {
  if (not -x $script) {
    die "Error, script is not executable: $script\n";
  }
}

# Usage
if (scalar(@ARGV) ne 2) {
  die "Usage: $0 test-pattern-for-redos-results.json normalizeByPumpGrowth\n";
  exit 0;
}

# Args
my $testResultsFile = $ARGV[0];

for my $file ($testResultsFile) {
  if (not -f $testResultsFile) {
    die "Error, no such file $testResultsFile\n";
  }
}

my $normalizeByPumpGrowth = $ARGV[1];

my $cont = &readFile("file"=>$testResultsFile);
my $json = decode_json($cont);

# For each detector, check how its evil input recommendations performed.
my $tmpFile = "/tmp/estimate-blowup-$$.csv";
unlink $tmpFile;
for my $do (@{$json->{detectorOpinions}}) {
  next unless ($do->{opinion}->{canAnalyze} and not $do->{opinion}->{isSafe});

  for my $evilInputType (keys %{$do->{dynamicResults}}) {
    my $growthPerPump = $do->{dynamicResults}->{$evilInputType}->{growthPerPump};
    #&log("evilInputType $evilInputType pumpResults\n  " . encode_json($do->{dynamicResults}->{$evilInputType}->{results}));

    for my $language (keys %{$do->{dynamicResults}->{$evilInputType}->{results}}) {
      my @slimPumpResults;
      for my $pumpResult (@{$do->{dynamicResults}->{$evilInputType}->{results}->{$language}->{pumpResults}}) {
        my $slimPumpResult = { "nPumps"         => $pumpResult->{nPumps},
                               "time"           => $pumpResult->{elapsedSec},
                               "normalizedTime" => $pumpResult->{elapsedSec} / $growthPerPump,
                             };
        push @slimPumpResults, $slimPumpResult;
      }

      # If there was a blow-up, remove noise.
      my $blowupThreshold = 0.1;
      if ($blowupThreshold < $slimPumpResults[-1]->{time}) {
        my $noiseThreshold = 0.05;
        while ($slimPumpResults[0]->{time} < $noiseThreshold) {
          shift @slimPumpResults;
        }
      }

      # Prep input to $fitCurve
      my @asCSV;
      my $label;
      if ($normalizeByPumpGrowth) {
        @asCSV = map { "$_->{nPumps},$_->{normalizedTime}" } @slimPumpResults;
        $label = "normalizedTime";
      }
      else {
        @asCSV = map { "$_->{nPumps},$_->{time}" } @slimPumpResults;
        $label = "time";
      }
      &writeToFile("file" => $tmpFile,
                   "contents" => "nPumps,$label\n" . join("\n", @asCSV));

      # Fit the curve and update the results
      my $curve = &fitCurve("csvFile"=>$tmpFile);
      unlink $tmpFile;

      $do->{dynamicResults}->{$evilInputType}->{results}->{$language}->{curve} = $curve;
    }
  }
}

print STDOUT encode_json($json) . "\n";
exit 0;

######################

# input: %args: keys: file
# output: $contents
sub readFile {
  my %args = @_;

	open(my $FH, '<', $args{file}) or confess "Error, could not read $args{file}: $!";
	my $contents = do { local $/; <$FH> }; # localizing $? wipes the line separator char, so <> gets it all at once.
	close $FH;

  return $contents;
}

# input: %args: keys: file contents
# output: $file
sub writeToFile {
  my %args = @_;

	open(my $fh, '>', $args{file});
	print $fh $args{contents};
	close $fh;

  return $args{file};
}

sub log {
  my ($msg) = @_;
  print STDERR "$msg\n";
}

# input: ($cmd)
# output: ($rc, $out)
sub cmd {
  my ($cmd) = @_;
  &log("CMD: $cmd");
  my $out = `$cmd`;
  return ($? >> 8, $out);
}

# input: (%args) keys: csvFile 
# output: ($curve) from $fitCurve.
#   hashref with keys: type [parms r2]
sub fitCurve {
  my (%args) = @_;
  my ($rc, $out) = &cmd("$fitCurve $args{csvFile} 2>/dev/null");
  if ($rc) {
    return { "type"=>"UNKNOWN" };
  }

  my $curve = decode_json($out);
  return $curve;
}
