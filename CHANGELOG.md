# Release History

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
