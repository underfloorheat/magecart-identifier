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

/*
|---------------------------------------------------------------------
| Handle CLI input
|
 */
const argv = require('yargs')
	.usage('Usage: node $0 [options] <url>')
	.example('$0 https://www.site.com', 'Test url for known vulnerabilities')
	.example('$0 -r', 'Output HTTP requests from url')
	.example('$0 -rp', 'Output HTTP requests excluding params')
	.example('$0 -rd', 'Show domains only in HTTP request output')
	.example('$0 -r -c javascript,jpg,png', 'Output HTTP requests for specific content-types')
	.example('$0 -f local-file.har', 'Use local HAR file instead of url')
	.example('$0 -w', 'Write HTTP requests to file instead of stdout')
	.alias('r', 'requests')
	.boolean(['r'])
	.describe('r', 'Output HTTP requests')
	.alias('p', 'params')
	.boolean(['p'])
	.describe('p', 'Exclude params from request output')
	.alias('d', 'domain-only')
	.boolean(['d'])
	.describe('d', 'Show domains only in HTTP request output')
	.alias('c', 'content-type')
	.describe('c', 'The content-type you want to output')
	.alias('f', 'har-file')
	.describe('f', 'Provide a local HAR file')
	.alias('w', 'write-to-file')
	.boolean(['w'])
	.describe('w', 'Write HTTP requests to file instead of stdout')
	.check((argv, options) => {
		const filePaths = argv._
		if (filePaths.length == 0) {
			if(argv.harFile == undefined) {
				throw new Error("You must supply either a URL or a local file")
			}
		} else {
			// Check we have a valid URL
			const uriPattern = /^(?:(?:(?:https?|ftp):)?\/\/)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:[/?#]\S*)?$/i;
			if(!uriPattern.test(filePaths[0])) {
				throw new Error('You have not entered a valid URL');
			}
		}
		return true
	})
	.help('h')
	.alias('h', 'help')
	.argv;

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
	if(argv.requests) {
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
		// Collate response URLs cleaning them up as we go based on the supplied CLI flags
		urls = _.map(entries, (entry) => {
			const entryUrl = new URL(entry.request.url);
			// Domains only
			if(argv.domainOnly) return entryUrl.origin;
			// Remove params
			if(argv.params) return entryUrl.origin + entryUrl.pathname;
			// Full url
			return entryUrl.href;
		});

		let sortedUrls = _.uniq(urls.sort());

		if(argv.writeToFile) {
			// Create the request file output directory if it doesn't exist
			if (!fs.existsSync(config.requestsOutputDirectory)){
		    	fs.mkdirSync(config.requestsOutputDirectory);
			}
			// Save the HAR file to disk
			await promisify(fs.writeFile)(
				config.requestsOutputDirectory + '/' + filename + '.har',
				JSON.stringify(sortedUrls, null, 4)
			);
		} else {
			for(const urlStr of sortedUrls) {
				console.log(urlStr);
			}
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
		for(let riskyUrl of riskyRequests) {
			console.log(riskyUrl);
		}
	} else {
		console.log('\nNo magecart indicators found');
	}

	/*-------------------------------------------------------------
	|
	|  Check HAR file content against expected domains list
	|
	*/

	try{
		const expected = require('./config/expected.json');
		// Create a RegEx pattern containing the magecart indicators
		let unexpectedRegEx = new RegExp(expected.join('|'));
		let unexpectedRequests = [];

		for(const entry of har.log.entries) {
			if(!unexpectedRegEx.test(entry.request.url)) {
				unexpectedRequests.push(entry.request.url);
			}
		}

		if(unexpectedRequests.length > 0) {
			console.log('\nUnexpected requests found.\n');
			for(let unexpectedUrl of unexpectedRequests) {
				console.log(unexpectedUrl);
			}
		} else {
			console.log('\nNo unexpected requests found');
		}
	} catch (e) {
		if (e instanceof Error && e.code === "MODULE_NOT_FOUND")
			console.log("no expected.json to check");
		else
			throw e;
	}


	console.log('\nThe full request HAR can be found at ' + __dirname
		+ '/' + config.harOutputDirectory
		+ '/' + filename + '.har\n');
})();