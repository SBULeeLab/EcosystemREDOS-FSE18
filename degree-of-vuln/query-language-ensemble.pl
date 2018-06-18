#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Query each of the languages for REDOS and return a coherent response.
#
# Options: Options are controlled by env vars.
#   - LANGUAGES   Which languages to test? X,Y,...         Defaults to all supported languages.
#   - PUMP_START  Start with this many pumps.              Default  1.
#   - PUMP_STRIDE Increase by this many per test.          Default  2. Can be non-integer e.g. for geometric stride.
#   - STRIDE_TYPE 'arithmetic' or 'geometric'.             Default  'arithmetic'.
#   - MAX_STRIDES Stop after timeout or this many strides. Default 30.
#   - TIMEOUT     Stop if match time ever exceeds this.    Default  3 (seconds).

use strict;
use warnings;

use IPC::Cmd qw[can_run]; # Check PATH
use JSON::PP; # I/O
use Time::HiRes qw( gettimeofday tv_interval );
use Carp;

# Check dependencies.
if (not defined $ENV{ECOSYSTEM_REGEXP_PROJECT_ROOT}) {
  die "Error, ECOSYSTEM_REGEXP_PROJECT_ROOT must be defined\n";
}
if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

my $validateVuln = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/validate/validate-vuln.pl";
if (not -x $validateVuln) {
  die "Error, could not find validateVuln <$validateVuln>\n";
}

# Check environment-variable parms
my $useAllLanguages = 1;
my @LANGUAGES;
if (defined($ENV{LANGUAGES})) {
  @LANGUAGES = split(",", $ENV{LANGUAGES});
  $useAllLanguages = 0;
}

my $PUMP_START = 1;
if (defined($ENV{PUMP_START})) {
  $PUMP_START = int($ENV{PUMP_START});
}
if ($PUMP_START <= 0) {
  die "Error, invalid PUMP_START $PUMP_START\n";
}
&log("PUMP_START $PUMP_START");

my $PUMP_STRIDE = 2;
if (defined($ENV{PUMP_STRIDE})) {
  $PUMP_STRIDE = $ENV{PUMP_STRIDE};
}
if ($PUMP_STRIDE <= 0) {
  die "Error, invalid PUMP_STRIDE $PUMP_STRIDE\n";
}
&log("PUMP_STRIDE $PUMP_STRIDE");

my $STRIDE_TYPE = "arithmetic";
if (defined($ENV{STRIDE_TYPE})) {
  $STRIDE_TYPE = lc $ENV{STRIDE_TYPE};
  if ($STRIDE_TYPE eq "arithmetic" or $STRIDE_TYPE eq "arith" or $STRIDE_TYPE eq "+"){
    $STRIDE_TYPE = "arithmetic";
  }
  elsif($STRIDE_TYPE eq "geometric" or $STRIDE_TYPE eq "geo" or $STRIDE_TYPE eq "*"){
    $STRIDE_TYPE = "geometric";
  }
  else {
    die "Error, invalid STRIDE_TYPE $STRIDE_TYPE\n";
  }
}
&log("STRIDE_TYPE $STRIDE_TYPE");

my $MAX_STRIDES = 30;
if (defined($ENV{MAX_STRIDES})) {
  $MAX_STRIDES = int($ENV{MAX_STRIDES});
}
&log("MAX_STRIDES $MAX_STRIDES");

my $TIMEOUT = 3;
if (defined($ENV{TIMEOUT})) {
  $TIMEOUT = int($ENV{TIMEOUT});
}
if ($TIMEOUT < 1) {
  die "Error, invalid TIMEOUT $ENV{TIMEOUT}\n";
}
&log("TIMEOUT $TIMEOUT");

# Get dynamic analyses
my @dynamicAnalyses = &getDynamicAnalyses();

# Filter by languages
if ($useAllLanguages) {
  @LANGUAGES = map { $_->{language} } @dynamicAnalyses;
}

@dynamicAnalyses = grep { &listContains(\@LANGUAGES, $_->{language}) } @dynamicAnalyses;
if (not @dynamicAnalyses) {
  die "Error, no dynamicAnalyses matched languages <@LANGUAGES>\n";
}
&log("Using languages <@LANGUAGES>");

# Check args.
if (scalar(@ARGV) != 1) {
  die "Usage: $0 pattern.json\n";
}

my $patternFile = $ARGV[0];
if (not -f $patternFile) {
  die "Error, no such patternFile $patternFile\n";
}

# Read.
my $cont = &readFile("file"=>$patternFile);
my $pattern = decode_json($cont);

# Now, for each detector opinion, we can run each analysis.
&log("Checking what each detector said about pattern /$pattern->{pattern}/");
for my $do (@{$pattern->{detectorOpinions}}) {
  &log("Checking $do->{name}");

  # Nothing to do if it's not vulnerable.
  if ($do->{opinion} eq "INTERNAL-ERROR") {
    &log("$do->{name} suffered an internal error");
    next;
  }
  if (not $do->{opinion}->{canAnalyze}) {
    &log("$do->{name} could not analyze");
    next;
  }
  if ($do->{opinion}->{timedOut}) {
    &log("$do->{name} timed out");
    next;
  }
  if ($do->{opinion}->{isSafe}) {
    &log("$do->{name} said pattern was safe");
    next;
  }
  &log("$do->{name} said it was vulnerable!");

  # Nothing to do without evil input.
  if (not $do->{opinion}->{evilInput}) {
    &log("$do->{name} did not propose evil input");
    next;
  }
  if ($do->{opinion}->{evilInput} eq "COULD-NOT-PARSE") {
    &log("Could not parse the evil input of $do->{name}");
    next;
  }

  &log("$do->{name}: Trying evil input");
  my $dynamicResults = &tryEvilInput("pattern"=>$pattern, "detectorOpinion"=>$do, "dynamicAnalyses"=>\@dynamicAnalyses);
  $do->{dynamicResults} = $dynamicResults;
}

print STDOUT encode_json($pattern) . "\n";
exit 0;

#####################

# input: ($cmd)
# output: ($rc, $out)
sub cmd {
  my ($cmd) = @_;
  &log("CMD: $cmd");
  my $out = `$cmd`;
  return ($? >> 8, $out);
}

sub log {
  my ($msg) = @_;
  print STDERR "$msg\n";
}

# input: (%args) keys: pattern detectorOpinion
# output: ($dynamicResults)
#   hashref with keys the various evilInputTypes ("eda", "ida")
#     each has value a hashref with keys: languages
#       each language has value a listref with elements: invalidPattern | nPumps elapsedSec timedOut
#       if invalidPattern, look no further
#       if !timedOut, additional keys: length matched
sub tryEvilInput {
  my (%args) = @_;
  my $do = $args{detectorOpinion};
  if (not defined $do or not @dynamicAnalyses) {
    die "tryEvilInput: Error, usage: hash with keys: do dynamicAnalyses\n";
  }

  my $tmpFile = "/tmp/query-language-ensemble-$$-$do->{name}.json";
  unlink $tmpFile;

  # Evil input x dynamic analyses x pumps
  my %dynamicResults;
  for my $evilInputType (keys %{$do->{opinion}->{evilInput}}) {
    my %evilInputResults;
    &log("$do->{name}: Trying evilInput $evilInputType");

    # Fill in @evilInputResults: one for each language
    for my $dynAnal (@dynamicAnalyses) {
      my @perLangResults;
      &log("$do->{name}: Trying language $dynAnal->{language}");

      # Fill in @perLangResults: one for each pump
      my $everTimedOut = 0;
      # Iterate over nStrides, updating nPumps appropriately.
      my $nPumps = $PUMP_START;
      for (my $nStrides = 0; $nStrides <= $MAX_STRIDES; $nStrides++) {
        &log("$do->{name}: $nPumps pumps ($nStrides strides)");

        # Formulate the query object.
        my $queryObject = { "pattern"   => $pattern->{pattern},
                            "evilInput" => $do->{opinion}->{evilInput}->{$evilInputType},
                            "nPumps"    => int($nPumps)
                          };
        &writeToFile("file"=>$tmpFile, "contents"=>encode_json($queryObject)); 

        # Run the analysis.
        my $t0 = [gettimeofday];
        my $ONE_GB_IN_BYTES = 1*1024*1024*1024;
        my $memoryLimit = 1 * $ONE_GB_IN_BYTES;
        my $memoryLimitCmds = "ulimit -m $memoryLimit; ulimit -v $memoryLimit";
        my ($rc, $out) = &cmd("$memoryLimitCmds; timeout ${TIMEOUT}s $dynAnal->{driver} $tmpFile 2>/dev/null");
        my $elapsed = tv_interval($t0);
        unlink $tmpFile;

        # Got language result: this many pumps took that long.
        my $stringLen = &computeEvilInputStringLen("evilInput"=>$do->{opinion}->{evilInput}->{$evilInputType}, "nPumps"=>$nPumps);
        my $result = { "nPumps"     => $nPumps,
                       "length"     => $stringLen,
                       "elapsedSec" => $elapsed
                     };
        # Timeout?
        if ($rc eq 124) {
          $result->{timedOut} = 1;
        }
        # Failed? (presumably a crash on unsupported pattern)
        elsif ($rc) {
          $result->{invalidPattern} = 1;
        }
        # Things worked!
        else {
          $result->{timedOut} = 0;
          $result->{invalidPattern} = 0;

          # Extract inputLength and whether or not it matched.
          if ($dynAnal->{language} eq "rust") {
            # Rust does not follow the usual API. Blurgh.
            $result->{matched} = ($out =~ m/matched: true/) ? 1 : 0;
          }
          else {
            my $queryResult = decode_json($out);
            $result->{matched} = $queryResult->{matched};
            $result->{exceptionString} = $queryResult->{exceptionString};
            if ($stringLen ne $queryResult->{inputLength}) {
              die "Error, queryResult length $queryResult->{inputLength} but I computed stringLen $stringLen\n";
            }
          }
        }

        push @perLangResults, $result;

        # If we timed out, no point in trying again.
        if ($result->{timedOut}) {
          &log("Timed out after $nPumps pumps, no point in trying longer strings");
          $everTimedOut = 1;
          last;
        }
        # If we couldn't handle this pattern, no point in trying again.
        if ($result->{invalidPattern}) {
          &log("$dynAnal->{language} failed on pattern /$pattern->{pattern}/");
          last;
        }

        # Increase nPumps by $PUMP_STRIDE based on the $STRIDE_TYPE
        if ($STRIDE_TYPE eq "arithmetic") {
          $nPumps += $PUMP_STRIDE;
        }
        else {
          $nPumps *= $PUMP_STRIDE;
        }
        $nPumps = &roundUp($nPumps); # Round up (esp. for geometric, non-integer stride)

      } # Loop over $nStrides

      # Got evil input result: performance on this language
      $evilInputResults{$dynAnal->{language}} = { "everTimedOut" => $everTimedOut,
                                                  "pumpResults"  => \@perLangResults
                                                };
    } # Loop over @dynamicAnalyses

    # Got dynamic result: performance on this evilInputType
    my @sizeOnPumps = map { &computeEvilInputStringLen("evilInput"=>$do->{opinion}->{evilInput}->{$evilInputType}, "nPumps"=>$_) } (1,2,3);
    my $growthPerPump = $sizeOnPumps[1] - $sizeOnPumps[0];
    if ($growthPerPump ne $sizeOnPumps[2] - $sizeOnPumps[1]) {
      die "Error, growthPerPump unpredictable??\n";
    }
    $dynamicResults{$evilInputType} = { "growthPerPump"  => $growthPerPump,
                                        "results" => \%evilInputResults,
                                      };
  } # Loop over $evilInputType

  return \%dynamicResults;
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

# input: %args: keys: evilInput nPumps
#  evilInput: keys pumpPairs suffix
# output: ($stringLen)
sub computeEvilInputStringLen {
  my (%args) = @_;

  my $stringLen = 0;
  for my $pumpPair (@{$args{evilInput}->{pumpPairs}}) {
    $stringLen += length($pumpPair->{prefix});
    $stringLen += $args{nPumps} * length($pumpPair->{pump});
  }
  $stringLen += length($args{evilInput}->{suffix});

  return $stringLen;
}

# input: %args: keys: file
# output: $contents
sub readFile {
  my %args = @_;

	open(my $FH, '<', $args{file}) or confess "Error, could not read $args{file}: $!";
	my $contents = do { local $/; <$FH> }; # localizing $? wipes the line separator char, so <> gets it all at once.
	close $FH;

  return $contents;
}

sub roundUp {
  my ($num) = @_;
  if (int($num) < $num) {
    return int($num + 1);
  }
  else {
    return int($num);
  }
}
