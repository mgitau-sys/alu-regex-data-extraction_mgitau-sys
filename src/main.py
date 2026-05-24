import re
import json
import os
import sys

# ── INPUT VALIDATION ──────────────────────────────────────────
INPUT_PATH = "../input/raw-text.txt"
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5MB limit to prevent memory exhaustion

# check if the file exists before doing anything
if not os.path.exists(INPUT_PATH):
    print("[ERROR] Input file not found.")
    sys.exit(1)

# reject files that are too large to prevent memory attacks
if os.path.getsize(INPUT_PATH) > MAX_FILE_SIZE_BYTES:
    print("[ERROR] Input file exceeds maximum allowed size (5MB). Aborting.")
    sys.exit(1)

# Read input file
try:
    with open(INPUT_PATH, "r", encoding="utf-8", errors="replace") as file:
        raw_text = file.read()
except Exception as e:
    print(f"[ERROR] Could not read input file: {e}")
    sys.exit(1)

# reject input with null bytes since that's a sign of a binary or hostile file
if "\x00" in raw_text:
    print("[ERROR] Input contains null bytes. Possible binary or hostile file. Aborting.")
    sys.exit(1)

# ── EMAIL EXTRACTION ──────────────────────────────────────────
# email's regex - stricter version that blocks leading/trailing dots in local part
email_regex = r"\b[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]{0,62}[a-zA-Z0-9])?@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
emails = re.findall(email_regex, raw_text) # find all emails with the pattern above
emails = list(set(emails)) # to remove duplicates

# Safety validation for emails
def is_safe_email(email):
    if len(email) > 254: # rejects emails longer than RFC allows (254 chars max)
        return False
    if re.search(r"[\r\n\x00]", email): # rejects emails with newlines to block header injection attacks
        return False
    if re.search(r"[<>\"'`;|&]", email): # rejects emails with special characters that could be used for injection
        return False
    if ".." in email: # rejects emails with consecutive dots since those aren't valid
        return False
    local, _, domain = email.rpartition("@")
    if len(local) > 64 or len(local) == 0: # rejects local part longer than 64 chars (RFC limit)
        return False
    if "." not in domain: # rejects domains with no dot since they can't be real
        return False
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

# stricter regex for ALU local parts - only allows letters, digits, dots and hyphens
alu_local_regex = re.compile(r"^[a-zA-Z0-9]+([.\-][a-zA-Z0-9]+)*$")

for email in emails:
    local = email.split("@")[0]
    if email.endswith("@alumni.alueducation.com"):
        if alu_local_regex.match(local): # make sure the local part is clean before accepting it
            alu_alumni.append(email)
    elif email.endswith("@si.alueducation.com"):
        if alu_local_regex.match(local):
            alu_si.append(email)
    elif email.endswith("@alueducation.com"):
        if alu_local_regex.match(local):
            alu_official.append(email)
    else:
        other_emails.append(email)

# ── CREDIT CARD EXTRACTION ────────────────────────────────────
# Regex for card numbers - matches 16 digit cards in plain, spaced or dashed format
card_regex = r"\b(?:\d{4}[ -]?){3}\d{4}\b"
cards = re.findall(card_regex, raw_text) # extracting the cards

# Luhn algorithm to check if a card number is actually valid and not just random digits
def luhn_check(number):
    digits = [int(d) for d in number]
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1: # double every second digit from the right
            d *= 2
            if d > 9: # if doubling gives more than 9, subtract 9
                d -= 9
        total += d
    return total % 10 == 0 # valid cards always have a total divisible by 10

# Cleaning the card numbers to remove spaces and dashes
cleaned_cards = []
for card in cards:
    cleaned = re.sub(r"[ -]", "", card)
    cleaned_cards.append(cleaned)

# Validating cards with Luhn check instead of just length
valid_cards = []
for card in cleaned_cards:
    if card.isdigit() and 13 <= len(card) <= 19 and luhn_check(card): # added luhn_check to filter out random digit strings
        valid_cards.append(card)

# Masking card numbers for security reasons
masked_cards = []
for card in valid_cards:
    masked = "**** **** **** " + card[-4:] # only show last 4 digits
    masked_cards.append(masked)

# ── PHONE NUMBER EXTRACTION ───────────────────────────────────
# Phone numbers regex
phone_regex = r"(?:\+\d{1,3}[\s\-.]?)?(?:\(\d{2,4}\)[\s\-.]?)?\d{2,4}[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}"
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
    if 7 <= len(digits_only) <= 15: # updated lower bound to 7 to match ITU-T standard for short local numbers
        valid_phones.append(phone)

valid_phones = list(set(valid_phones)) # this removes duplicates

# ── URL EXTRACTION ────────────────────────────────────────────
# URL regex
url_regex = r"https?://[^\s\"'<>]+"
urls = re.findall(url_regex, raw_text) # extracting urls
urls = list(set(urls)) # removing duplicate urls

# blocking private IP ranges and localhost to avoid SSRF attacks where the app could be tricked into hitting internal servers
BLOCKED_URL_PATTERNS = re.compile(
    r"(localhost|127\.0\.0\.1|0\.0\.0\.0|"
    r"10\.\d+\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|"
    r"172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+)",
    re.IGNORECASE
)

# Validating safe urls
safe_urls = []
for url in urls:
    if len(url) > 2048: # rejects urls longer than 2048 chars since browsers cap at that anyway
        continue
    if BLOCKED_URL_PATTERNS.search(url): # rejects urls pointing to internal/private networks
        continue
    if re.search(r"\.\./|\.\.\\", url): # rejects urls with path traversal patterns like ../../
        continue
    safe_urls.append(url)

# ── BUILD OUTPUT ──────────────────────────────────────────────
result = {
    "security_note": "Sensitive data is masked. Input was validated before processing.",
    "emails": {
        "alu_official": alu_official,
        "alu_alumni": alu_alumni,
        "alu_si": alu_si,
        "others": other_emails,
    },
    "credit_cards": {
        "total_found": len(masked_cards),
        "note": "Numbers masked — only last 4 digits shown", # added note so anyone reading the output knows why cards look like that
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

print("=== EXTRACTION SUMMARY ===")
print(f"Emails found:       {len(emails)}")
print(f"  └─ ALU official:  {len(alu_official)}")  # breakdown by ALU category
print(f"  └─ ALU alumni:    {len(alu_alumni)}")
print(f"  └─ ALU SI:        {len(alu_si)}")
print(f"  └─ Other:         {len(other_emails)}")
print(f"Credit cards found: {len(masked_cards)} (Luhn-validated, masked)")
print(f"Phone numbers found:{len(valid_phones)}")
print(f"URLs found:         {len(safe_urls)}")

# ── SAVE OUTPUT ───────────────────────────────────────────────
os.makedirs("../output", exist_ok=True)

with open("../output/sample_output.json", "w", encoding="utf-8") as f:
    json.dump(result, f, indent=4, ensure_ascii=False)

print("Done! Output saved to ../output/sample_output.json")