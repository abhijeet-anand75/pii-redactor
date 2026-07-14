"""
Sample texts for testing PII detection.
"""

SAMPLE_TEXT_WITH_PII = """
KSH INTERNATIONAL LIMITED
Registered Office: 11/3, 11/4 and 11/5, Village Birdewadi, Chakan Taluka - Khed, 
Pune – 410 501, Maharashtra, India

Contact Person: Sarthak Malvadkar, Company Secretary and Compliance Officer
Email: cs.connect@kshinternational.com
Telephone: +91 20 45053237
Website: www.kshinternational.com

Our Promoters: Kushal Subbayya Hegde, Pushpa Kushal Hegde, Rajesh Kushal Hegde, 
Rohit Kushal Hegde, Rakhi Girija Shetty
"""

SAMPLE_TEXT_WITHOUT_PII = """
The quick brown fox jumps over the lazy dog. 
This is a test document with no personally identifiable information.
It contains only common words and phrases.
"""

SAMPLE_EMAILS = [
    "john.doe@example.com",
    "jane.smith@company.co.uk",
    "test.user+filter@gmail.com",
    "admin@subdomain.domain.com"
]

SAMPLE_PHONES = [
    "+91 9876543210",
    "9876543210",
    "0 9876543210",
    "+91 98765 43210"
]

SAMPLE_NAMES = [
    "John Smith",
    "Mary Johnson",
    "Kushal Subbayya Hegde",
    "Rashi Patil"
]

SAMPLE_ADDRESSES = [
    "123 Main Street, Mumbai, Maharashtra 400001",
    "11/3, Village Birdewadi, Chakan, Pune 410501",
    "201, Tower 2, Montreal Business Centre, Baner, Pune 411045"
]