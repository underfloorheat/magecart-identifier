# magecart-identifier

> HAR scanning for known magecart indicators

## Usage

	node app.js [options] <url>

	Options:
	  --version       Show version number                                  [boolean]
	  -r, --requests  Only output HTTP requests                            [boolean]
	  -e, --exclude   Exclude params from request output                   [boolean]
	  -h, --help      Show help                                            [boolean]

	Examples:
	  node app.js https://www.site.com      Test url for known vulnerabilities
	  node app.js -r https://www.site.com   Only output HTTP requests from url
	  node app.js -re https://www.site.com  Output HTTP requests excluding params

## What it's doing

The script will, using [puppeteer](https://github.com/puppeteer/puppeteer), load the given url and make all subsequent HTTP calls requested within the html.  A [HAR](http://www.softwareishard.com/blog/har-12-spec/) file will be generated of all requests, using [chrome-har](https://github.com/sitespeedio/chrome-har), and tested against the following domains/IP's: -

* payment-mastercard.com
* google-query.com
* google-analytics.top
* google-smart.com
* google-payment.com
* jquery-assets.com
* sagepay-live.com
* google-query.com
* payment-sagepay.com
* payment-worldpay.com
* 124.156.34.157
* 47.245.55.198
* 5.53.124.235
* jsboxcontents.com
* ms-akadns.com
* survey-microsoft.net
* cnzz.work
* 45.76.97.191
* 54.215.230.114
* cnzz.space
* 45.76.97.191
* 139.180.207.51
* 202.181.24.14
* 103.230.122.162
* sdsyxwx.com
* 45.76.97.191

The HAR file will also be saved in a directory called `har_files` in the root of this project for further analysis.

## Version 2 functional wishlist

I'll be looking at adding the following functionality to this module: -

* Notification system to send an email if a threat is found
* Logging system for archival investigation
* Secondary script which adds item to basket, loads checkout and tests redirection URLs against expected payment gateways