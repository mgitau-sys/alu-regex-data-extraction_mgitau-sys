#Project structure

alu-regex-data-extraction/
├── input/
│   └── raw-text.txt          
├── output/
│   └── sample_output.json    
└── src/
└── main.py               
#What It Does

The script reads a raw messy text file and extracts four types of data:

- **Emails** — extracts all emails and sorts them into categories:
  - ALU Official (@alueducation.com)
  - ALU Alumni (@alumni.alueducation.com)
  - ALU SI (@si.alueducation.com)
  - Other (gmail, yahoo, outlook, etc.)
- **Credit Cards** — extracts card numbers, validates length, and masks all
  but the last 4 digits for security
- **Phone Numbers** — extracts and validates phone numbers from multiple
  formats and country codes
- **URLs** — extracts and validates all URLs found in the text

#How To Run

1 Place your input file in the input/folder and name it raw-text.txt

2 Navigate to the src/ folder in your terminal:


cd src

3 Run the script:

python main.py

4 Your results will be saved to output/sample_output.json

#Output Format

json
{
  "emails": {
    "all_valid": [],
    "alu_official": [],
    "alu_alumni": [],
    "alu_si": [],
    "others": []
  },
  "credit_cards": {
    "total_found": 0,
    "masked_cards": []
  },
  "phone_numbers": {
    "total_found": 0,
    "numbers": []
  },
  "urls": {
    "total_found": 0,
    "links": []
  }
}


#Requirements

- Python 3.x
- No external libraries needed — only built-in modules re, json, and os

#Security Features

- Emails containing html tags like script are rejected
- Emails with spaces are rejected
- Credit card numbers are masked — only last 4 digits are visible
- Phone numbers are validated against international length standards (10–15 digits)
- Only http:// and https:// URLs are accepted