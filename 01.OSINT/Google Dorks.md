# Google Dorks
```table-of-contents
```
## Theory: Search Operators
| **Operator**      | **Description**                             | **Example**                | **Use Case**                                        |
| ------------- | --------------------------------------- | ---------------------- | ----------------------------------------------- |
| `site:`       | Limit results to a specific domain.     | `site:target.com`      | Find all indexed pages of the target.           |
| `inurl:`      | Search for terms inside the URL.        | `inurl:login`          | Find login pages or admin panels.               |
| `filetype:`   | Search for specific file extensions.    | `filetype:pdf`         | Find leaked documents, logs, or backups.        |
| `intitle:`    | Search for terms inside the page title. | `intitle:"index of"`   | Find open directory listings.                   |
| `intext:`     | Search for terms inside the body text.  | `intext:"password"`    | Find pages leaking credentials.                 |
| `cache:`      | Show Google's cached version of a page. | `cache:target.com`     | View content even if the site is down.          |
| `link:`       | Find pages linking to a specific URL.   | `link:target.com`      | Analyze backlinks.                              |
| `related:`    | Find sites similar to the target.       | `related:target.com`   | Discover competitors or related infrastructure. |
| `ext:`        | Same as filetype (Extension).           | `ext:log`              | Find log files exposed online.                  |
| `allintext:`  | Page must contain ALL terms in body.    | `allintext:admin pass` | Specific targeted search.                       |
| `exclude (-)` | Remove results containing a term.       | `site:target.com -www` | Find subdomains excluding the main www site.    |
## Useful Dorks for Pentesters
### Directory Listings
```http
site:target.com intitle:"index of"
site:target.com intitle:"index of" "parent directory"
```
### Configuration Files
```http
site:target.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ini
site:target.com filetype:env "DB_PASSWORD"
```
### Log Files
```http
site:target.com ext:log
site:target.com inurl:log
```
### Database Files
```http
site:target.com ext:sql | ext:dbf | ext:mdb
site:target.com "dump" "sql"
```
### Login Portals
```http
site:target.com inurl:admin
site:target.com inurl:login
site:target.com intitle:"login"
site:target.com inurl:portal
```
### Cloud Storage (S3 Buckets)
```http
site:s3.amazonaws.com "target"
```
## Automated Tools
- **Google Hacking Database (GHDB):** [https://www.exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database)
- **Pagodo:** Automates Google Dorking using GHDB.
- **Katana:** A modern crawler/dorking tool.