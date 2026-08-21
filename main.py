# ---------------------------------------------------------
# WEEK 8 - Q1
# Immutable, Leakage-Safe Training Corpus
# ---------------------------------------------------------

# hashlib gives us SHA-256.
import hashlib

# json is used to read JSONL rows and create compact JSON.
import json

# math is used to check whether contaminationThreshold is finite.
import math

# re is used for validating timestamps, CRC, generation, URI, etc.
import re

# unicodedata is needed for Unicode NFKC normalization
# and Unicode letter/number detection.
import unicodedata

# datetime is needed for timestamp validation and UTC conversion.
from datetime import datetime, timezone

# FastAPI creates the web API.
from fastapi import FastAPI, Request

# JSONResponse lets us explicitly return HTTP 400 when needed.
from fastapi.responses import JSONResponse


# Create the FastAPI application.
app = FastAPI()


# ---------------------------------------------------------
# REGULAR EXPRESSIONS
# ---------------------------------------------------------

# Valid timestamp:
# YYYY-MM-DDTHH:mm:ss[.sss](Z|±HH:mm)
#
# Fractional seconds can contain only 1, 2, or 3 digits.
TIME_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?P<fraction>\.\d{1,3})?"
    r"(?P<tz>Z|[+-]\d{2}:\d{2})$"
)


# Basic Google Storage URI:
# gs://bucket/object
URI_RE = re.compile(r"^gs://[^/\s]+/[^\s]+$")


# A generation must contain only decimal digits.
DECIMAL_RE = re.compile(r"^[0-9]+$")


# CRC32C must be exactly 8 LOWERCASE hexadecimal characters.
CRC_RE = re.compile(r"^[0-9a-f]{8}$")


# Maximum JavaScript safe integer.
SAFE_INTEGER_MAX = 2**53 - 1


# ---------------------------------------------------------
# SMALL HELPER FUNCTIONS
# ---------------------------------------------------------

def strict_json_loads(value):
    """
    Parse strict JSON.

    Python normally accepts NaN, Infinity and -Infinity,
    although they are not valid JSON.
    We reject them.
    """

    def reject_invalid_constant(constant):
        raise ValueError(
            f"Invalid JSON constant: {constant}"
        )

    return json.loads(
        value,
        parse_constant=reject_invalid_constant
    )
def utf8_key(value):
    """
    Convert a string to UTF-8 bytes.

    The assignment specifically says sorting must use UTF-8 bytes.
    """
    return value.encode("utf-8")


def compact_json(value):
    """
    Convert an object to compact JSON.

    ensure_ascii=False means non-ASCII Unicode characters are written
    directly instead of becoming \\uXXXX sequences.

    separators removes spaces.
    """
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":")
    )


# ---------------------------------------------------------
# CRC32C
# ---------------------------------------------------------

def crc32c_hex(text):
    """
    Calculate CRC32C over the EXACT UTF-8 bytes of content.

    IMPORTANT:
    CRC32C is NOT the same thing as normal zlib.crc32().
    """

    # Standard CRC32C starting value.
    crc = 0xFFFFFFFF

    # Process every UTF-8 byte.
    for byte in text.encode("utf-8"):

        crc ^= byte

        # Process all 8 bits in this byte.
        for _ in range(8):

            if crc & 1:
                crc = (crc >> 1) ^ 0x82F63B78
            else:
                crc >>= 1

    # Final XOR and convert to exactly 8 lowercase hex digits.
    return f"{(crc ^ 0xFFFFFFFF) & 0xFFFFFFFF:08x}"


# ---------------------------------------------------------
# TIMESTAMP VALIDATION + UTC NORMALIZATION
# ---------------------------------------------------------

def parse_event_time(value):
    """
    Validate a timestamp and convert it to:

    YYYY-MM-DDTHH:mm:ss.sssZ

    Returns None if invalid.
    """

    # Must be a string.
    if not isinstance(value, str):
        return None

    # First check the required textual format.
    match = TIME_RE.fullmatch(value)

    if match is None:
        return None

    # Extract timezone part.
    tz_part = match.group("tz")

    # Validate ±HH:mm timezone.
    if tz_part != "Z":

        # Characters 1-2 contain hour.
        offset_hour = int(tz_part[1:3])

        # Characters 4-5 contain minute.
        offset_minute = int(tz_part[4:6])

        # Offset cannot exceed 14 hours.
        if offset_hour > 14:
            return None

        # Minute must be 00-59.
        if offset_minute > 59:
            return None

        # ±14 is only allowed as ±14:00.
        if offset_hour == 14 and offset_minute != 0:
            return None

    # Get optional fractional second.
    fraction = match.group("fraction")

    # Python can parse ISO timestamps easily after we prepare them.
    if fraction is None:

        # No fraction was supplied.
        # Add .000.

        if tz_part == "Z":

            iso_text = value[:-1] + ".000+00:00"

        else:

            iso_text = (
                value[:-len(tz_part)]
                + ".000"
                + tz_part
            )

    else:

        # Remove the "." and pad fraction to exactly 3 digits.
        fraction_digits = fraction[1:].ljust(3, "0")

        padded_fraction = "." + fraction_digits

        if tz_part == "Z":

            iso_text = (
                value[:-1 - len(fraction)]
                + padded_fraction
                + "+00:00"
            )

        else:

            iso_text = (
                value[:-len(tz_part) - len(fraction)]
                + padded_fraction
                + tz_part
            )

    try:

        # Python validates actual calendar values here:
        # month, date, hour, minute, second, etc.
        parsed = datetime.fromisoformat(iso_text)

        # Convert the time to UTC.
        utc_time = parsed.astimezone(timezone.utc)

    except (ValueError, OverflowError):

        # Invalid calendar/time.
        return None

    # Always output exactly three millisecond digits.
    milliseconds = utc_time.microsecond // 1000

    return (
        utc_time.strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{milliseconds:03d}Z"
    )


# ---------------------------------------------------------
# CANONICALIZATION
# ---------------------------------------------------------

def canonicalize_text(value):
    """
    Required canonicalization:

    1. Unicode NFKC
    2. lowercase
    3. trim
    4. collapse Unicode whitespace to one ASCII space
    """

    # Unicode compatibility normalization.
    value = unicodedata.normalize("NFKC", value)

    # Convert to lowercase.
    value = value.lower()

    # Remove whitespace from beginning/end.
    value = value.strip()

    # Collapse any run of Unicode whitespace into one normal space.
    value = re.sub(
        r"\s+",
        " ",
        value,
        flags=re.UNICODE
    )

    return value


# ---------------------------------------------------------
# CONTAMINATION TOKENIZATION
# ---------------------------------------------------------

def word_set(text):
    """
    Create a set of lowercase Unicode letter/number words.

    A character is part of a word if its Unicode category
    starts with L (Letter) or N (Number).
    """

    words = set()

    current_word = []

    # The specification says lowercase.
    for char in text.lower():

        # Example:
        # L = Letter
        # N = Number
        # P = Punctuation
        category = unicodedata.category(char)

        if category.startswith("L") or category.startswith("N"):

            current_word.append(char)

        else:

            # Non-letter/number ends the current word.
            if current_word:

                words.add("".join(current_word))

                current_word = []

    # Add the final word if the text ended with a letter/number.
    if current_word:

        words.add("".join(current_word))

    return words


def jaccard(left_text, right_text):
    """
    Calculate Jaccard similarity:

        intersection size
        -----------------
           union size

    Empty/empty must equal 1.
    """

    left = word_set(left_text)

    right = word_set(right_text)

    # Required special case.
    if not left and not right:
        return 1.0

    union = left | right

    if not union:
        return 1.0

    intersection = left & right

    return len(intersection) / len(union)


# ---------------------------------------------------------
# POLICY VALIDATION
# ---------------------------------------------------------

def validate_policy(policy):
    """
    Validate minTime, maxTime and contaminationThreshold.

    Returns normalized policy if valid.
    Otherwise returns None.
    """

    # Policy must itself be an object.
    if not isinstance(policy, dict):
        return None

    # Validate and normalize the two times.
    min_time = parse_event_time(policy.get("minTime"))

    max_time = parse_event_time(policy.get("maxTime"))

    # Read contamination threshold.
    threshold = policy.get("contaminationThreshold")

    # Invalid time means invalid policy.
    if min_time is None or max_time is None:
        return None

    # Boolean is technically an int in Python,
    # so explicitly reject True and False.
    if isinstance(threshold, bool):
        return None

    # Threshold must be numeric.
    if not isinstance(threshold, (int, float)):
        return None

    # Convert to float.
    threshold = float(threshold)

    # Must be finite.
    if not math.isfinite(threshold):
        return None

    # Must be between 0 and 1 inclusive.
    if not (0.0 <= threshold <= 1.0):
        return None

    # A minimum after maximum is not a valid time window.
    if min_time > max_time:
        return None

    return {
        "minTime": min_time,
        "maxTime": max_time,
        "contaminationThreshold": threshold,
    }


# ---------------------------------------------------------
# OBJECT VALIDATION
# ---------------------------------------------------------

def validate_and_read_object(obj):
    """
    Validate one supplied object.

    If valid:
        returns accepted data, None

    If invalid:
        returns None, rejected-object record
    """

    reason_codes = []

    # Safely extract fields.
    if isinstance(obj, dict):

        raw_uri = obj.get("uri")

        generation = obj.get("generation")

        fetched_generation = obj.get("fetchedGeneration")

        crc = obj.get("crc32c")

        schema_id = obj.get("schemaId")

        content = obj.get("content")

    else:

        # A completely invalid object.
        raw_uri = None

        generation = None

        fetched_generation = None

        crc = None

        schema_id = None

        content = None


    # -----------------------------------------------------
    # URI validation
    # -----------------------------------------------------

    if (
        not isinstance(raw_uri, str)
        or URI_RE.fullmatch(raw_uri) is None
    ):

        reason_codes.append("URI_INVALID")


    # -----------------------------------------------------
    # GENERATION validation
    # -----------------------------------------------------

    generation_supplied = (
        isinstance(obj, dict)
        and "generation" in obj
    )

    fetched_generation_supplied = (
        isinstance(obj, dict)
        and "fetchedGeneration" in obj
    )
    # generation must be a decimal string.
    generation_valid = (
        isinstance(generation, str)
        and DECIMAL_RE.fullmatch(generation) is not None
    )
    fetched_generation_valid = (
        isinstance(fetched_generation, str)
        and DECIMAL_RE.fullmatch(fetched_generation) is not None
    )

    # Either invalid -> GENERATION_INVALID.
    if not generation_valid or not fetched_generation_valid:

        reason_codes.append("GENERATION_INVALID")

    # GENERATION_MISMATCH applies when both fields were supplied
    # but their values are different.
    if (
        generation_supplied
        and fetched_generation_supplied
        and generation != fetched_generation
    ):

        reason_codes.append("GENERATION_MISMATCH")


    # -----------------------------------------------------
    # CRC32C validation
    # -----------------------------------------------------

    crc_valid = (
        isinstance(crc, str)
        and CRC_RE.fullmatch(crc) is not None
    )

    if not crc_valid:

        reason_codes.append("CRC32C_INVALID")

    # CRC mismatch is checked only when:
    # 1. CRC syntax is valid
    # 2. content is a string
    elif isinstance(content, str):

        calculated_crc = crc32c_hex(content)

        if calculated_crc != crc:

            reason_codes.append("CRC32C_MISMATCH")


    # -----------------------------------------------------
    # SCHEMA ID + CONTENT TYPE
    # -----------------------------------------------------

    if (
        schema_id != "training-v1"
        or not isinstance(content, str)
    ):

        reason_codes.append("SCHEMA_INVALID")


    # This will contain canonicalized rows.
    parsed_rows = []


    # -----------------------------------------------------
    # JSONL
    # -----------------------------------------------------

    if isinstance(content, str):

        nonblank_line_count = 0

        # splitlines handles \n and \r\n correctly.
        for line in content.splitlines():

            # Blank lines must be ignored.
            if line.strip() == "":
                continue

            nonblank_line_count += 1

            # Try to parse this JSON line.
            try:

                row = strict_json_loads(line)

            except (json.JSONDecodeError, ValueError):
                # Parsing failure.
                reason_codes.append("JSONL_INVALID")

                continue


            # -------------------------------------------------
            # Each row must be a JSON object.
            # -------------------------------------------------

            if not isinstance(row, dict):

                reason_codes.append("SCHEMA_INVALID")

                continue


            # Required EXACT row keys.
            expected_keys = {
                "id",
                "entity",
                "eventTime",
                "revision",
                "text"
            }

            # No missing keys and no extra keys.
            if set(row.keys()) != expected_keys:

                reason_codes.append("SCHEMA_INVALID")

                continue


            # -------------------------------------------------
            # Four string fields
            # -------------------------------------------------

            string_fields_are_valid = all(
                isinstance(row[key], str)
                for key in (
                    "id",
                    "entity",
                    "eventTime",
                    "text"
                )
            )

            if not string_fields_are_valid:

                reason_codes.append("SCHEMA_INVALID")

                continue


            # -------------------------------------------------
            # revision
            # -------------------------------------------------

            revision = row["revision"]

            # Must be:
            # - integer
            # - not boolean
            # - >= 0
            # - <= JS safe integer
            if (
                isinstance(revision, bool)
                or not isinstance(revision, int)
                or revision < 0
                or revision > SAFE_INTEGER_MAX
            ):

                reason_codes.append("SCHEMA_INVALID")

                continue


            # -------------------------------------------------
            # eventTime
            # -------------------------------------------------

            normalized_time = parse_event_time(
                row["eventTime"]
            )

            if normalized_time is None:

                reason_codes.append("SCHEMA_INVALID")

                continue


            # -------------------------------------------------
            # Canonical row
            #
            # IMPORTANT: create keys in EXACT required order:
            #
            # id
            # entity
            # eventTime
            # revision
            # text
            # -------------------------------------------------

            canonical_row = {
                "id": row["id"],

                "entity": canonicalize_text(
                    row["entity"]
                ),

                "eventTime": normalized_time,

                "revision": revision,

                "text": canonicalize_text(
                    row["text"]
                ),
            }

            parsed_rows.append(canonical_row)


        # File must have at least one nonblank row.
        if nonblank_line_count == 0:

            reason_codes.append("SCHEMA_INVALID")


    # -----------------------------------------------------
    # Sort + deduplicate object reason codes
    # -----------------------------------------------------

    reason_codes = sorted(
        set(reason_codes),
        key=utf8_key
    )


    # -----------------------------------------------------
    # Reject complete object if ANY object error occurred
    # -----------------------------------------------------

    if reason_codes:

        # URI must become null if supplied URI wasn't a string.
        rejected_object = {
            "uri": (
                raw_uri
                if isinstance(raw_uri, str)
                else None
            ),

            "reasonCodes": reason_codes,
        }

        return None, rejected_object


    # -----------------------------------------------------
    # Accepted object lineage
    # -----------------------------------------------------

    lineage = {
        "uri": raw_uri,
        "generation": generation,
        "crc32c": crc,
        "schemaId": schema_id,
    }


    return {
        "rows": parsed_rows,
        "lineage": lineage,
    }, None


# ---------------------------------------------------------
# REJECTED ROW HELPER
# ---------------------------------------------------------

def reject_row(rejected_rows, row_id, *codes):
    """
    Add one rejected-row record.
    """

    reason_codes = sorted(
        set(codes),
        key=utf8_key
    )

    rejected_rows.append({
        "id": row_id,
        "reasonCodes": reason_codes,
    })


# ---------------------------------------------------------
# DEDUPLICATION
# ---------------------------------------------------------

def deduplicate_rows(rows, rejected_rows):
    """
    Deduplicate using:

        [entity, eventTime, text]

    Winner:
    1. highest revision
    2. UTF-8-byte-smallest ID
    """

    groups = {}


    # Group rows by the required tuple.
    for row in rows:

        key = (
            row["entity"],
            row["eventTime"],
            row["text"],
        )

        groups.setdefault(key, []).append(row)


    winners = []


    # Process each duplicate group.
    for group in groups.values():

        # Sort so the winner appears first.
        ordered = sorted(
            group,
            key=lambda row: (
                # Negative means higher revision first.
                -row["revision"],

                # Then smallest UTF-8 ID.
                utf8_key(row["id"]),

                # Deterministic final tie-breaker.
                compact_json(row).encode("utf-8"),
            ),
        )


        # First row survives.
        winner = ordered[0]

        winners.append(winner)


        # Every other row is DUPLICATE.
        for loser in ordered[1:]:

            reject_row(
                rejected_rows,
                loser["id"],
                "DUPLICATE"
            )


    return winners


# ---------------------------------------------------------
# TRAIN / VALIDATION / TEST BUCKET
# ---------------------------------------------------------

def split_bucket(entity):
    """
    bucket =
        first byte of SHA256(UTF8(entity)) % 10

    0-5 -> train
    6-7 -> validation
    8-9 -> test
    """

    # SHA-256 raw 32-byte digest.
    digest = hashlib.sha256(
        entity.encode("utf-8")
    ).digest()


    # Get first byte.
    first_byte = digest[0]


    # Modulo 10.
    bucket = first_byte % 10


    if bucket <= 5:

        return "train"


    if bucket <= 7:

        return "validation"


    return "test"


# ---------------------------------------------------------
# SORT SPLIT ROWS
# ---------------------------------------------------------

def sort_rows(rows):
    """
    Sort by:
    1. UTF-8 bytes of ID
    2. compact JSON
    """

    return sorted(
        rows,
        key=lambda row: (
            utf8_key(row["id"]),
            compact_json(row).encode("utf-8"),
        ),
    )


# ---------------------------------------------------------
# SHA-256 SPLIT DIGEST
# ---------------------------------------------------------

def digest_rows(rows):
    """
    Serialize each row as compact JSON,
    append one newline after EVERY row,
    then SHA-256 the exact UTF-8 bytes.
    """

    payload = "".join(
        compact_json(row) + "\n"
        for row in rows
    )

    return hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------
# RESPONSE SORTING
# ---------------------------------------------------------

def sort_rejected_objects(items):
    """
    Sort rejected objects by URI UTF-8 bytes.

    null URI is placed before string URIs.
    Compact JSON is used as tie-breaker.
    """

    def key(item):

        uri = item["uri"]

        if uri is None:

            primary = b""

        else:

            primary = uri.encode("utf-8")

        return (
            primary,
            compact_json(item).encode("utf-8")
        )

    return sorted(items, key=key)


def sort_rejected_rows(items):
    """
    Sort rejected rows by ID UTF-8 bytes,
    then compact JSON.
    """

    return sorted(
        items,
        key=lambda item: (
            item["id"].encode("utf-8"),
            compact_json(item).encode("utf-8"),
        ),
    )


def sort_lineage(items):
    """
    Sort lineage by URI UTF-8 bytes,
    then compact JSON.
    """

    return sorted(
        items,
        key=lambda item: (
            item["uri"].encode("utf-8"),
            compact_json(item).encode("utf-8"),
        ),
    )


# ---------------------------------------------------------
# MAIN ENDPOINT
# ---------------------------------------------------------

@app.post("/build-corpus")
async def build_corpus(request: Request):

    # -----------------------------------------------------
    # Read request JSON manually.
    # -----------------------------------------------------

    try:

        # Read the exact incoming HTTP body.
        raw_body = await request.body()

        # JSON must be valid UTF-8.
        body_text = raw_body.decode("utf-8")

        # Parse using strict JSON rules.
        body = strict_json_loads(body_text)

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ):

        # Invalid JSON request.
        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )


    # -----------------------------------------------------
    # Top-level validation
    #
    # Missing policy OR non-array objects
    # must return HTTP 400 exactly:
    #
    # {"error":"INVALID_INPUT"}
    # -----------------------------------------------------

    if (
        not isinstance(body, dict)
        or "policy" not in body
        or not isinstance(body.get("objects"), list)
    ):

        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )


    # -----------------------------------------------------
    # Validate policy
    # -----------------------------------------------------

    policy = validate_policy(
        body["policy"]
    )


    # All rows from valid objects.
    accepted_rows = []


    # Object rejection output.
    rejected_objects = []


    # Row rejection output.
    rejected_rows = []


    # Valid object lineage.
    lineage = []


    # -----------------------------------------------------
    # Validate every supplied object
    # -----------------------------------------------------

    for obj in body["objects"]:

        accepted, rejected = (
            validate_and_read_object(obj)
        )


        # Object failed validation.
        if rejected is not None:

            rejected_objects.append(
                rejected
            )

            continue


        # Object passed validation.
        accepted_rows.extend(
            accepted["rows"]
        )


        lineage.append(
            accepted["lineage"]
        )


    # -----------------------------------------------------
    # Deduplication
    # -----------------------------------------------------

    retained_rows = deduplicate_rows(
        accepted_rows,
        rejected_rows
    )


    # Required split object.
    splits = {
        "train": [],
        "validation": [],
        "test": [],
    }


    # -----------------------------------------------------
    # Invalid policy
    # -----------------------------------------------------

    if policy is None:

        # Every deduplicated retained row is rejected.
        for row in retained_rows:

            reject_row(
                rejected_rows,
                row["id"],
                "POLICY_INVALID"
            )


    # -----------------------------------------------------
    # Valid policy
    # -----------------------------------------------------

    else:

        in_window_rows = []


        # -------------------------------------------------
        # Inclusive time window
        # -------------------------------------------------

        for row in retained_rows:

            if not (
                policy["minTime"]
                <= row["eventTime"]
                <= policy["maxTime"]
            ):

                reject_row(
                    rejected_rows,
                    row["id"],
                    "OUT_OF_WINDOW"
                )

                continue


            in_window_rows.append(row)


        # -------------------------------------------------
        # Initial deterministic hash splitting
        # -------------------------------------------------

        candidate_splits = {
            "train": [],
            "validation": [],
            "test": [],
        }


        for row in in_window_rows:

            split_name = split_bucket(
                row["entity"]
            )


            candidate_splits[
                split_name
            ].append(row)


        # -------------------------------------------------
        # Train rows are accepted immediately.
        # -------------------------------------------------

        train_rows = candidate_splits[
            "train"
        ]


        splits["train"] = train_rows


        # Contamination threshold.
        threshold = policy[
            "contaminationThreshold"
        ]


        # -------------------------------------------------
        # Check validation + test contamination
        # -------------------------------------------------

        for split_name in (
            "validation",
            "test"
        ):

            for row in candidate_splits[
                split_name
            ]:

                # Compare this text against EVERY train row.
                contaminated = any(

                    jaccard(
                        row["text"],
                        train_row["text"]
                    ) >= threshold

                    for train_row in train_rows
                )


                # Reject contaminated validation/test row.
                if contaminated:

                    reject_row(
                        rejected_rows,
                        row["id"],
                        "TRAIN_CONTAMINATION"
                    )


                # Otherwise keep it.
                else:

                    splits[
                        split_name
                    ].append(row)


    # -----------------------------------------------------
    # Sort the three split rows
    # -----------------------------------------------------

    for split_name in splits:

        splits[split_name] = sort_rows(
            splits[split_name]
        )


    # -----------------------------------------------------
    # Sort all deterministic response sections
    # -----------------------------------------------------

    rejected_objects = sort_rejected_objects(
        rejected_objects
    )


    rejected_rows = sort_rejected_rows(
        rejected_rows
    )


    lineage = sort_lineage(
        lineage
    )


    # -----------------------------------------------------
    # SHA-256 digests
    # -----------------------------------------------------

    digests = {

        "train": digest_rows(
            splits["train"]
        ),

        "validation": digest_rows(
            splits["validation"]
        ),

        "test": digest_rows(
            splits["test"]
        ),
    }


    # -----------------------------------------------------
    # EXACT required response shape
    # -----------------------------------------------------

    return {

        "splits": splits,

        "rejectedObjects": rejected_objects,

        "rejectedRows": rejected_rows,

        "digests": digests,

        "lineage": lineage,
    }
