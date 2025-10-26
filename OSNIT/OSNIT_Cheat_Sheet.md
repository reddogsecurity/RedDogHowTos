# OSINT Cheat Sheet


Google dorking is a technique that uses advanced search operators to find specific information that is publicly available on the internet but not easily discovered with standard search queries.

Google dorking is an authoritative way to query the many corners of the Google search engine. Its contents are search terms that can reveal usernames, passwords, and files containing sensitive information.

---

| Operator          | Description                                                                        |
| ----------------- | ---------------------------------------------------------------------------------- |
| `"Search Term"`   | Search for the exact phrase (use quotation marks).                                 |
| `-`               | Exclude pages that contain a given term from the results.                          |
| `+`               | Force the search engine to return common words that might ordinarily be discarded. |
| `OR`              | Search for one term OR another.                                                    |
| `site:`           | Search within a given domain (e.g., `site:example.com`).                           |
| `filetype:`       | Search for a certain file type (e.g., `filetype:pdf`).                             |
| `intitle:`        | Search for pages with the given word(s) in the page title.                         |
| `inurl:`          | Search for pages with the given word(s) in the URL.                                |
| `intext:`         | Search for pages with the given word(s) in the page body.                          |
| `inanchor:`       | Search for pages that have the given word(s) in links pointing to them.            |
| `cache:`          | Show the most recent cached copy of a webpage.                                     |
| `IP:`             | Bing only — find results based on a specific IP address.                           |
| `linkfromdomain:` | Bing only — search for links on the given domain.                                  |

## Additional Google Features

- Search Tools: The Tools button offers options that let you narrow results (for example, a Custom range to limit by date).

- Google Images: A powerful reverse image search service — https://images.google.com/

---

## Searching for Archived Information

- Google and Bing: Both search engines provide a cached view of results.

- The Wayback Machine: https://archive.org/web/

- Archive Today: https://archive.is/

---

# Yandex

Yandex operates the largest search engine in Russia (roughly ~65% market share in Russia).

## Yandex Search Operators

| Operator          | Description                                                                                                       |
| `"I * music"`     | Find results with any word where the asterisk (`*`) is placed.                                                    |
| `Cheshire cat                                               | hatter                                                                  |
| `croquet +flamingo`                                         | Requires the page to contain `flamingo`, but not necessarily `croquet`. |
| `rhost:org.wikipedia.*`                                     | Reverse host search.                                                    |
| `mime:pdf`                                                  | Search for a specific file type.                                        |
| `!Curiouser !and !curiouser`                                | Search for multiple identical words.                                    |
| `Twinkle twinkle little -star`                              | Exclude `star` from results.                                            |
| `lang:en`                                                   | Narrow search by language.                                              |
| `date:200712*`, `date:20071215..20080101`, `date:>20091231` | Narrow search by date or date range.                                    |

---

# Search Engines: Other Alternatives

- carrot2.org — Carrot2 is a clustering search engine that groups results into topics.

- millionshort.com — MillionShort allows removing the top N most popular results (e.g., remove the 1,000,000 most popular sites).

---

# Shodan — https://www.shodan.io

Shodan is a search engine for finding Internet-connected devices and device types. Use it to search for webcams, routers, IoT/SCADA devices, and more.

## Shodan Filters

| Filter      | Description                                                       |
| ----------- | ----------------------------------------------------------------- |
| `city:`     | Search for results in a given city.                               |
| `country:`  | Search for results in a given country (use 2-letter code).        |
| `port:`     | Search for a specific port or ports.                              |
| `hostname:` | Match values in the hostname.                                     |
| `net:`      | Search a given IP or subnet (e.g., `192.168.1.0/24`).             |
| `product:`  | Search for the software product name as identified in the banner. |
| `version:`  | Search for the product version.                                   |
| `os:`       | Search for a specific operating system.                           |
| `title:`    | Search text scraped from the HTML `<title>` tag.                  |
| `html:`     | Search inside the full HTML content that Shodan scraped.          |

---

#  Social Networks

## Facebook

- ### Search bar: Can find profiles created using a given email address or phone number (if those fields are public or leaked).

- ### Facebook ID: The Facebook user ID can be found using services such as https://findmyfbid.com
  Alternatively, while logged into Facebook, the UserID can sometimes be found in the page source after the fb://profile/ tag.

### Facebook Graph Search (examples)

### Places

- Places visited: /search/UserID/places

- Places recently visited: /search/UserID/places-visited

- Places checked in: /search/UserID/recent-places-visited

- Places liked: /search/UserID/places-liked

### Pages & Likes

- Pages liked: /search/UserID/pages-liked

- Page likers: /likers (append to a page URL)

### Photos

- Photos of: /search/UserID/photos

- Photos by: /search/UserID/photos-of

- Photos liked: /search/UserID/photos-liked

- Photos commented: /search/UserID/photos-commented

### Videos

- Videos of: /search/UserID/videos

- Videos by: /search/UserID/videos-of

- Videos liked: /search/UserID/videos-liked

- Videos commented: /search/UserID/videos-commented

### Events

- Events joined (example): /search/UserID/events

- Events joined in 2010 (example): /search/str/UserID/events-joined/2010/date/events/intersect/

### Posts

- Posts tagged: /search/UserID/stories-by

- Posts liked: /search/UserID/stories-liked

- Posts by year: /search/UserID/stories-by/2010/date/stories/intersect

### Friends / Connections

- Friends: /search/UserID/friends

- Followers: /search/UserID/followers

- Groups: /search/UserID/groups

- Employers / Co-workers: /search/UserID/employers, /search/UserID/employees

### Additional Facebook graph queries:

- https://inteltechniques.com/

- http://researchclinic.net/graph.html

---

## Twitter (X) Search Operators

| Operator                            | Finds Tweets…                                              |
| ----------------------------------- | ---------------------------------------------------------- |
| `twitter search`                    | Containing both `twitter` and `search` (default behavior). |
| `"happy hour"`                      | Containing the exact phrase `happy hour`.                  |
| `love OR hate`                      | Containing `love` or `hate` (or both).                     |
| `beer -root`                        | Containing `beer` but not `root`.                          |
| `#haiku`                            | Containing the hashtag `haiku`.                            |
| `from:alexiskold`                   | Sent from user `alexiskold`.                               |
| `to:techcrunch`                     | Sent to user `techcrunch`.                                 |
| `@mashable`                         | Referencing user `mashable`.                               |
| `"happy hour" near:"san francisco"` | Containing exact phrase and sent from `san francisco`.     |
| `near:NYC within:15mi`              | Sent from within 15 miles of NYC.                          |
| `superhero since:2010-12-27`        | Containing `superhero` and sent since the specified date.  |
| `ftw until:2010-12-27`              | Containing `ftw` and sent up to the specified date.        |
| `hilarious filter:links`            | Containing `hilarious` and linking to URLs.                |
| `news source:"Twitter Lite"`        | Containing `news` and posted via Twitter Lite.             |
| `geocode:47.37,8.541,10km`          | Sent from within 10 km of the given coordinates.           |


| Additional Twitter queries: https://twitter.com/search-advanced and https://inteltechniques.com

---

## Social Networks — User Enumeration

Many social platforms leak small bits of information via features that can be abused for user enumeration.

| Feature           | Twitter | Facebook | Instagram | LinkedIn | 
| ----------------- | ------- | -------- | --------- | -------- |
| Registration      | X       | X        | X         | X        |
| Password recovery | X       | X        | X         | X        |
| Search bar        | X       |          |           |          |
				

| Note: password recovery flows on Facebook and Twitter sometimes disclose the last two digits of the registered mobile number — useful for narrowing identity.

---

## Tools

| Tool                 | Description                                                                                                                                      |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Maltego**          | A powerful OSINT framework for infrastructure and personal reconnaissance.                                                                       |
| **FOCA**             | Extracts metadata and hidden information from scanned documents found on web pages. ([https://www.elevenpaths.com](https://www.elevenpaths.com)) |
| **Intel Techniques** | A broad collection of OSINT techniques and tools. [https://inteltechniques.com](https://inteltechniques.com)                                     |
| **Robtex**           | Aggregates public information about IP addresses, domain names, ASNs, routes, etc. [https://www.robtex.com/](https://www.robtex.com/)            |

---

## Additional Links

- Have I Been Pwned: https://haveibeenpwned.com — search for compromised accounts.

- DNS Dumpster: https://dnsdumpster.com — find hosts related to a domain.

- crt.sh: https://crt.sh — search Certificate Transparency logs.


---

## Books

- Google Hacking for Penetration Testers — Johnny Long

- Open Source Intelligence Techniques — Michael Bazzell

- Privacy and Security — Michael Bazzell

- Hiding from the Internet — Michael Bazzell