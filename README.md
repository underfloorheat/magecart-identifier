# magecart-identifier

HAR scanning for known magecart indicators

## Usage

	node app.js [options] <url>

	Options:
	  --version           Show version number                              [boolean]
	  -r, --requests      Output HTTP requests                             [boolean]
	  -p, --params        Exclude params from request output               [boolean]
	  -c, --content-type  The content-type you want to output
	  -d, --domain-only   Show domains only in HTTP request output         [boolean]
	  -h, --help          Show help                                        [boolean]

	Examples:
	  node app.js https://www.site.com          Test url for known vulnerabilities
	  node app.js -r https://www.site.com       Output HTTP requests from url
	  node app.js -r -p https://www.site.com    Output HTTP requests excluding
	                                            params
	  node app.js -r                            Output HTTP requests for specific
	  --content-type=javascript,jpg,png         content-types
	  https://www.site.com
	  node app.js -rd https://www.site.com      Show domains only in HTTP request
	                                            output

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

By using the -r and -p flags, you can also use this tool to simply output the url's of all HTTP requests your page is making.  This will allow for a manual look at what's going on.  I've recently added the --content-type (or -c) flag allowing a comma separated list of which mime types you want to review in the output.

## Version 2 functional wishlist

I'll be looking at adding the following functionality to this module: -

* Notification system to send an email if a threat is found
* Logging system for archival investigation
* Secondary script which adds item to basket, loads checkout and tests redirection URLs against expected payment gateways