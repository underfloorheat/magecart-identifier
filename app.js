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

let myArgs = process.argv.slice(2);

if(myArgs.length == 0) {
	console.log('You must supply a test page uri.');
	return false;
}

const filename = myArgs[0].split('/').pop();
const uri = myArgs[0];

const fs = require('fs');
const { promisify } = require('util');

const puppeteer = require('puppeteer');
const { harFromMessages } = require('chrome-har');

// list of events for converting to HAR
const events = [];

const harOutputDirectory = 'har_files';

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

(async () => {
	// Build regex pattern
	let regExPattern;
	await fs.readFile('url-patterns.txt', (err, data) => {
		if (err) throw err;
		regExPattern = new RegExp(data.toString().trim().split('\n').join('|'));
	});

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

	await promisify(fs.writeFile)(harOutputDirectory + '/' + filename + '.har', JSON.stringify(har, null, 4));

	let riskyRequests = [];

	for(let entry of har.log.entries) {
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
		console.log('\nNo threats found');
	}
	console.log('\nThe full request HAR can be found at ' + __dirname + '/' + filename + '.har\n');
})();