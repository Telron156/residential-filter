# Residential Filter

Automated IP address scraper and checker.

1. **Scrapes** IP lists from URLs provided in `sources.txt`.
2. **Validates** their availability.
3. **Filters** by latency (< 2500ms).
4. **Removes Datacenter IPs** (AWS, Google Cloud, Azure, DigitalOcean, etc.), retaining only "residential-like" addresses.

## How to Run

1. Install Node.js.
2. Download this repository.
3. Run the following commands in the project folder:
   ```bash
   npm install
   npm start

