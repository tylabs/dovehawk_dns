# Dovehawk.io Passive DNS Collector Module for Zeek

This module colects DNS requested names and multiple answers across an entire Cluster or Standalone Zeek instance.  The requestor is not tracked and SUMSTATS is used to aggregate multiple requests over a specified time period anonymizing the requests.

Local hostnames are stripped to further anonymize the data for external sharing.

![Sticker 1](https://dovehawk.io/images/dovehawk_sticker1.png "Sticker 1") ![Sticker 2](https://dovehawk.io/images/dovehawk_sticker2.png "Sticker 2")

## Screencaps

### DoveHawk pDNS Reported

![Dovehawk pDNS Reports](https://dovehawk.io/images/dovehawk_dns.png "Dovehawk pDNS")


### DoveHawk pdns.log Local Log

![Dovehawk pDNS Log](https://dovehawk.io/images/pdnslog.png "Dovehawk pDNS Log")


## Requirements

Zeek > 2.6.1 (Some 2.5 versions may work but testing showed issues with triggering the SUMSTATS finished epoch).

Curl command line version used by ActiveHTTP


## Database

See [dovehawk_lambda](https://github.com/tylabs/dovehawk_lambda) for an AWS Lambda serverless function to store reporting in RDS Aurora.


## Contact

Tyler McLellan [@tylabs](https://twitter.com/tylabs)

