import re
import json
import os

# Read input file
with open("../input/raw-text.txt", "r", encoding="utf-8") as file:
    raw_text = file.read()

# ── EMAIL EXTRACTION ──────────────────────────────────────────
# email's regex
email_regex = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
emails = re.findall(email_regex, raw_text) # find all emails with the pattern above
emails = list(set(emails)) # to remove duplicates

# Safety validation for emails
def is_safe_email(email):
    if "<script>" in email.lower(): # rejects emails containing <script>
        return False
    if " " in email: # rejects emails with spaces
        return False
    return True

emails = [e for e in emails if is_safe_email(e)]

# Creating empty lists to store different category of emails
alu_official = []
alu_alumni = []
alu_si = []
other_emails = []

for email in emails:
    if email.endswith("@alumni.alueducation.com"):
        alu_alumni.append(email)
    elif email.endswith("@si.alueducation.com"):
        alu_si.append(email)
    elif email.endswith("@alueducation.com"):
        alu_official.append(email)
    else:
        other_emails.append(email)

# ── CREDIT CARD EXTRACTION ────────────────────────────────────
# Regex for card numbers
card_regex = r"\b(?:\d[ -]*?){13,19}\b"
cards = re.findall(card_regex, raw_text) # extracting the cards

# Cleaning the card numbers to remove spaces and dashes
cleaned_cards = []
for card in cards:
    cleaned = re.sub(r"[ -]", "", card)
    cleaned_cards.append(cleaned)

# Validating cards length
valid_cards = []
for card in cleaned_cards:
    if card.isdigit() and 13 <= len(card) <= 19:
        valid_cards.append(card)

# Masking card numbers for security reasons
masked_cards = []
for card in valid_cards:
    masked = "*" * (len(card) - 4) + card[-4:]
    masked_cards.append(masked)

# ── PHONE NUMBER EXTRACTION ───────────────────────────────────
# Phone numbers regex
phone_regex = r"(?:\+\d{1,3}[\s-]?)?(?:\d{2,4}[\s-]?){2,4}\d{2,4}"
phones = re.findall(phone_regex, raw_text) # extracting phone numbers

# Cleaning the phone numbers to remove spaces and hyphen
cleaned_phones = []
for phone in phones:
    cleaned = re.sub(r"[\s-]", "", phone)
    cleaned_phones.append(cleaned)

# Validating Phone Numbers
valid_phones = []
for phone in cleaned_phones:
    digits_only = re.sub(r"\D", "", phone)
    if 10 <= len(digits_only) <= 15:
        valid_phones.append(phone)

valid_phones = list(set(valid_phones)) # this removes duplicates

# ── URL EXTRACTION ────────────────────────────────────────────
# URL regex
url_regex = r"https?://[^\s\"'>]+"
urls = re.findall(url_regex, raw_text) # extracting urls
urls = list(set(urls)) # removing duplicate urls

# Validating safe urls
safe_urls = []
for url in urls:
    if url.startswith("http://") or url.startswith("https://"):
        safe_urls.append(url)

# ── BUILD OUTPUT ──────────────────────────────────────────────
result = {
    "emails": {
        "alu_official": alu_official,
        "alu_alumni": alu_alumni,
        "alu_si": alu_si,
        "others": other_emails,
    },
    "credit_cards": {
        "total_found": len(masked_cards),
        "masked_cards": masked_cards,
    },
    "phone_numbers": {
        "total_found": len(valid_phones),
        "numbers": valid_phones,
    },
    "urls": {
        "total_found": len(safe_urls),
        "links": safe_urls,
    }
}

# ── SAVE OUTPUT ───────────────────────────────────────────────
os.makedirs("../output", exist_ok=True)

with open("../output/sample_output.json", "w", encoding="utf-8") as f:
    json.dump(result, f, indent=4, ensure_ascii=False)

print("Done! Output saved to ../output/sample_output.json")