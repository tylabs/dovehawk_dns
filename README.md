# Dovehawk.io Passive DNS Collector Module for Zeek

This module colects DNS requested names and multiple answers across an entire Cluster or Standalone Zeek instance.  The requestor is not tracked and SUMSTATS is used to aggregate multiple requests over a specified time period anonymizing the requests.

Local hostnames are stripped to further anonymize the data for external sharing.

# Requirements

Zeek > 2.6.1 (Some 2.5 versions may work but testing showed issues with triggering the SUMSTATS finished epoch.

Curl command line version used by ActiveHTTP


# Database

See dovehawk_lambda for a AWS Lambda serverless function.

