# SecureCheck

A Flask web app to check a link before you click it and test a password before you use it.

## Features
- Sign up and log in (passwords are stored as hashes, never as plain text)
- Link checker: looks for common phishing signs such as no HTTPS, IP address instead of a name, '@' tricks, shortened links, many sub-domains and scam words
- Password strength checker: rates a password as Weak, Medium or Strong and gives tips
- Dashboard that keeps each user's scan history (passwords themselves are never saved)

## Built with
Python, Flask, SQLite, HTML, CSS

## Run it on your computer
```
pip install -r requirements.txt
python app.py
```
Then open http://127.0.0.1:5000 in your browser.

## Project structure
- `app.py` - the whole backend: database, checker logic and pages
- `templates/` - the HTML pages
- `static/style.css` - the styling

## Note
The link checker only reads the text of a link. It does not open the website, so it gives warnings, not a guarantee.
