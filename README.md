# PII Redaction Tool

## Overview

A production-quality tool for detecting and redacting Personally Identifiable Information (PII) from PDF documents. The tool uses a hybrid detection approach combining regular expressions, Named Entity Recognition (NER), and heuristic rules to identify 9 different types of PII with high precision and recall.

### Core Philosophy

- **Precision over Recall (Default):** The default configuration prioritizes precision to avoid over-redaction, which can render documents unusable. Confidence thresholds can be adjusted by the user.
- **Modular Architecture:** Each PII type has its own recognizer, making the system easily extensible.
- **Format Preservation:** The tool attempts to preserve the original document's layout and structure.
- **Deterministic Replacement:** Fake values are generated deterministically for consistency across runs.

## Approach

### Detection Strategy

The tool employs a **hybrid detection strategy** to maximize accuracy:

1. **Pattern-Based Detection (Regex):** Used for highly structured PII types like Email, Phone, SSN, Credit Card, and IP Address.
2. **Rule-Based Detection (SpaCy + Rules):** Used for Full Names using SpaCy's NER model with additional rule-based heuristics.
3. **Contextual Analysis:** For dates of birth and addresses, the system analyzes surrounding context to determine if a date is likely a DOB.

### Replacement Strategy

- **Seed-Based Generation:** All fake data is generated using a seeded Faker instance (default seed: 42), ensuring consistent output across runs.
- **Type-Specific Fakers:** Each PII type uses an appropriate faker (e.g., Faker.email() for emails, Faker.name() for names).
- **Consistency:** The same PII text always gets the same fake value throughout the document, maintaining internal consistency.

### PDF Processing

- **Text Extraction:** Uses PyPDF2 to extract text from PDF documents.
- **Format Preservation:** Attempts to preserve original text positions using reportlab.
- **Fallback:** If precise positioning fails, a simpler overlay method is used.

## Supported PII Types

| PII Type | Detection Method | Example |
|----------|------------------|---------|
| Email Address | Regex Pattern | john.doe@example.com |
| Phone Number | Regex Pattern (Indian) | +91 9876543210 |
| Full Name | SpaCy NER + Rules | John Smith |
| SSN | Regex + Validation | 123-45-6789 |
| Credit Card | Regex + Luhn Validation | 4111-1111-1111-1111 |
| IP Address | Regex Pattern | 192.168.1.1 |
| Date of Birth | Regex + Context | 25/12/1990 |
| Physical Address | Regex + Heuristics | 123 Main St, Mumbai |
| Company Name | (Future Enhancement) | KSH International |

## Evaluation Approach

The tool's performance is evaluated using three standard metrics:

### Metrics
- **Precision:** Percentage of detected entities that are correct (`TP / (TP + FP)`)
- **Recall:** Percentage of actual PII that was detected (`TP / (TP + FN)`)
- **F1 Score:** Harmonic mean of precision and recall (`2 * (P * R) / (P + R)`)

### Ground Truth Comparison
The evaluation works by comparing detected PII entities against a manually annotated "ground truth" JSON file. The ground truth file contains the exact positions and types of all PII in the document.

**Ground Truth Format:**
```json
[
    {"text": "john.doe@example.com", "start": 8, "end": 27, "type": "EMAIL"},
    {"text": "John Smith", "start": 0, "end": 10, "type": "FULL_NAME"}
]