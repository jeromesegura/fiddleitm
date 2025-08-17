# Release History

## August 17 2025: fiddleitm 1.0.3

- Improved rules parsing based on request or response phases
  (previously the sames rules where parsed twice: on request and response)

## May 27 2025: fiddleitm 1.0.2

- Simplified version check to improve backwards compatibility

## May 25 2025: fiddleitm 1.0.1

- Added option to clear comments from flows (fiddleitm.clear @all)

## May 24 2025: fiddleitm 1.0

- complete rewrite
- new rules engine (JSON)

## February 1 2025: fiddleitm 0.5

- added Google Ads and CAPTCHA detection

## January 15 2025: fiddleitm 0.4

- improved local logging
- added option to drop traffic with media files

## December 9 2024: fiddleitm 0.3

- Fixed a bug with fiddleitm.search

## November 26 2024: fiddleitm 0.2.9

- Added support for response body SHA256 rules

## October 30 2024: fiddleitm 0.2.8

- Added Chrome and Edge domains exclusion to prevent unicode errors when browsers update
  
## October 29 2024: fiddleitm 0.2.7

- Corrected typo ( flow.request.headers["Referer"] to flow.request.headers["referer"])

## October 25 2024: fiddleitm 0.2.6

- Improved search feature (fiddleitm.search @all)

## October 9 2024: fiddleitm 0.2.5

- Added support for both single and double quotes when writing rules
- Improved the clear command

## August 26 2024: fiddleitm 0.2.4

- Changed web columns order
- Added a local filter option
- Migrated to @jeromesegura

## August 9 2024: fiddleitm 0.2.3

- Fixed a bug with connect-the-dots

## August 9 2024: fiddleitm 0.2.2

- Added new command to clear all comments from mitmweb UI (fiddleitm.clear @all)
- Improved connect-the-dots feature
- Added filters (filters.txt) to skip certain hostnames causing decoding errors
- Added rule scanning for content-type: application/json

## August 5 2024: fiddleitm 0.2.1

- Fixed a bug that would occur if you ran mitmdump using the new index column ids

## July 29 2024: fiddleitm 0.2

- Index column # [#7039](https://github.com/mitmproxy/mitmproxy/pull/7039) to visualize flow sequences is now available (requires mitmproxy 10.4.0)
- Added updater to check for and download new fiddleitm script. Updater also displays what the latest mitmproxy version is.
- Improved search to look in response headers (mitm.search @all [search term])
- Added connect-the-dots feature (fiddleitm.connect @all [flow index]). This allows to link flows together and retrace a delivery method.

Many thanks to @mhils and the mitmproxy contributors for all their continued efforts.

## July 7 2024: fiddleitm 0.1

- original release with most functionality after various pre-releases
