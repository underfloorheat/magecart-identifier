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
	.alias('r', 'requests')
	.boolean(['r'])
	.describe('r', 'Output HTTP requests')
	.alias('p', 'params')
	.boolean(['p'])
	.describe('p', 'Exclude params from request output')
	.alias('c', 'content-type')
	.describe('c', 'The content-type you want to output')
	.demandCommand(1)
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
const path = require('path')
const fs = require('fs');
const { promisify } = require('util');
const puppeteer = require('puppeteer');
const { harFromMessages } = require('chrome-har');

// list of events for converting to HAR
const events = [];

// event types to observe
const observe = [
	'Page.loadEventFired',
	'Page.domContentEventFired',
	'Page.frameStartedLoading',
	'Page.frameAttached',
	'Network.requestWillBeSent',
	'Network.requestServedFromCache',
	'Network.dataReceived',
	'Network.responseReceived',
	'Network.resourceChangedPriority',
	'Network.loadingFinished',
	'Network.loadingFailed'
];

// Create the har file output directory if it doesn't exist
if (!fs.existsSync(config.harOutputDirectory)){
    fs.mkdirSync(config.harOutputDirectory);
}

(async () => {

	const browser = await puppeteer.launch();
	const page = await browser.newPage();

	// register events listeners
	const client = await page.target().createCDPSession();
	await client.send('Page.enable');
	await client.send('Network.enable');
	observe.forEach(method => {
		client.on(method, params => {
			events.push({ method, params });
		});
	});

	await page.goto(uri);
	await browser.close();

	// convert events to HAR file
	const har = harFromMessages(events);

	// Save the HAR file to disk
	await promisify(fs.writeFile)(
		config.harOutputDirectory + '/' + filename + '.har',
		JSON.stringify(har, null, 4)
	);

	/*-------------------------------------------------------------
	|
	|  Output HTTP requests
	|
	*/
	if(argv.r) {
		let urls = [];
		const entries = _.filter(har.log.entries, (entry) => {
			if(argv.c == undefined) {
				return true;
			}
			let entryIndex = _.findIndex(entry.response.headers, (header) => {
				for(let c of _.split(argv.c, ',')) {
					if(_.toLower(header.name) == 'content-type' && _.includes(_.toLower(header.value), c)) {
						return true;
					}
				}
				return false;
			});
			return entryIndex > 0 ? true : false;
		});

		urls = _.map(entries, (entry) => {
			return argv.p ? entry.request.url.split('?')[0] : entry.request.url;
		});

		for(const url of urls.sort()) {
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