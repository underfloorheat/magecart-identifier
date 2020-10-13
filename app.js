/*
|--------------------------------------------------------------------------
| MageCart testing script
|--------------------------------------------------------------------------
|
| This script will examine the full HAR file for the given request
| and flag if any of the known MageCart urls are being called.  These url
| patterns can be found in the url-patterns.txt file
|
| Copyright(c) 2020 Chris Sewell
| GNU general public license
|
*/
'use strict';


const argv = require('yargs')
	.usage('Usage: node $0 [options] <url>')
	.example('node $0 https://www.site.com', 'Test url for known vulnerabilities')
	.example('node $0 -r https://www.site.com', 'Output HTTP requests from url')
	.example('node $0 -r -p https://www.site.com', 'Output HTTP requests excluding params')
	.example('node $0 -r --content-type=javascript,jpg,png https://www.site.com', 'Output HTTP requests for specific content-types')
	.example('node $0 -rd https://www.site.com', 'Show domains only in HTTP request output')
	.alias('r', 'requests')
	.boolean(['r'])
	.describe('r', 'Output HTTP requests')
	.alias('p', 'params')
	.boolean(['p'])
	.describe('p', 'Exclude params from request output')
	.alias('c', 'content-type')
	.describe('c', 'The content-type you want to output')
	.alias('d', 'domain-only')
	.boolean(['d'])
	.describe('d', 'Show domains only in HTTP request output')
	.demandCommand(1)
	.alias('c', 'content-type')
	.describe('c', 'The content-type you want to output')
	.help('h')
	.alias('h', 'help')
	.argv;

// Check we have a valid URL
const uriPattern = /^(?:(?:(?:https?|ftp):)?\/\/)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:[/?#]\S*)?$/i;
const uri = argv._[0];
if(!uriPattern.test(uri)) {
	console.log('You have not entered a valid URL');
	return false;
}
// Set the HAR file filename
const filename = uri.split('?')[0]
					.split('/')
					.pop();
/*
|---------------------------------------------------------------------
| We have everything we need from the user so lets get started
|
 */
const config = require('config');
const _ = require('lodash');
const url = require('url');
const fs = require('fs');
const { promisify } = require('util');
const { getHarFile } = require('./har.js');

(async () => {

	let har = {};
	let filename = '';

	/**
	 * Get a HAR file either from one being passed or by generating
	 * a new one using puppeteer
	 */
	if(argv.harFile != undefined) { // We've been passed a HAR file
		if(!fs.existsSync(argv.harFile)) {
			throw new Error("The HAR file path you provided doesn't exist");
		}
		har = JSON.parse(fs.readFileSync(argv.harFile));
		if(har.log.entries == undefined) {
			throw new Error("You've supplied an invalid HAR file");
		}
	} else { // We've been passed a URL and need to generate the HAR file

		// Create a URL object for use later
		const uri = new URL(argv._[0]);

		// Set the HAR file filename
		filename = uri.pathname.split('/').pop();

		// Create the har file output directory if it doesn't exist
		if (!fs.existsSync(config.harOutputDirectory)){
		    fs.mkdirSync(config.harOutputDirectory);
		}

		// Generate the HAR file
		har = await getHarFile(uri);

		// Save the HAR file to disk
		await promisify(fs.writeFile)(
			config.harOutputDirectory + '/' + filename + '.har',
			JSON.stringify(har, null, 4)
		);
	}

	/*-------------------------------------------------------------
	|
	|  Output HTTP requests
	|
	*/
	if(argv.r) {
		let urls = [];
		// Filter for content type
		const entries = _.filter(har.log.entries, (entry) => {
			if(argv.contentType == undefined) {
				return true;
			}
			let entryIndex = _.findIndex(entry.response.headers, (header) => {
				for(let c of _.split(argv.contentType, ',')) {
					if(_.toLower(header.name) == 'content-type'
						&& _.includes(_.toLower(header.value), c)) {
						return true;
					}
				}
				return false;
			});
			return entryIndex > 0 ? true : false;
		});
		// Collate response URLs
		urls = _.map(entries, (entry) => {
			const entryUrl = new URL(entry.request.url);
			// Domains only
			if(argv.d) {
				return entryUrl.origin;
			}
			// Remove params
			if(argv.p) {
				return entryUrl.origin + entryUrl.pathname;
			}
			// Full url
			entryUrl.href;
		});

		for(const url of _.uniq(urls.sort())) {
			console.log(url);
		}
	}

	/*-------------------------------------------------------------
	|
	|  Check HAR file content against known magecart indicators
	|
	*/

	// Create a RegEx pattern containing the magecart indicators
	let regExPattern = new RegExp(config.indicators.join('|'));
	let riskyRequests = [];

	for(const entry of har.log.entries) {
		if(regExPattern.test(entry.request.url)) {
			riskyRequests.push(entry.request.url);
		}
	}

	if(riskyRequests.length > 0) {
		console.log('\nUnauthorised url(s) found.\n');
		for(let url of riskyRequests) {
			console.log(url);
		}
	} else {
		console.log('\nNo magecart indicators found');
	}

	console.log('\nThe full request HAR can be found at ' + __dirname
		+ '/' + config.harOutputDirectory
		+ '/' + filename + '.har\n');
})();